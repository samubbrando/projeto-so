#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <linux/in.h>
#include "common/hist.h"
#include "net-funcs.h"
#include "rtt.h"
#include "cgroup_manager.h"
#include "speed_estimator.h"

#define MAX_RULES 256

struct proc_prev
{
    char pid[16];
    uint64_t timestamp_ns;
    unsigned long long tx_bytes;
    unsigned long long rx_bytes;
};

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static int read_socket_data(struct bpf_map *hists_map,
                             socket_proccess_t *sockets, int n_sockets)
{
    int count = 0;
    for (int i = 0; i < n_sockets; i++)
    {
        if (sockets[i].pid[0] == '\0') continue;

        struct conn_key ck = {0};
        if (inet_pton(AF_INET, sockets[i].src_ip, &ck.src_ip) != 1) continue;
        ck.src_port = sockets[i].src_port;
        if (inet_pton(AF_INET, sockets[i].end_ip, &ck.dst_ip) != 1) continue;
        ck.dst_port = sockets[i].end_port;
        ck.protocol = 6;

        struct hist val;
        if (bpf_map__lookup_elem(hists_map, &ck, sizeof(ck),
                                 &val, sizeof(val), 0) == 0)
        {
            sockets[i].tx_bytes = val.sent;
            sockets[i].rx_bytes = val.received;
            sockets[i].rtt = val.rtt;
            count++;
        }
    }
    return count;
}

static int read_udp_socket_data(struct bpf_map *udp_map,
                                 socket_proccess_t *sockets, int n_sockets)
{
    int count = 0;
    for (int i = 0; i < n_sockets; i++)
    {
        if (sockets[i].pid[0] == '\0') continue;

        struct conn_key ck = {0};
        if (inet_pton(AF_INET, sockets[i].src_ip, &ck.src_ip) != 1) continue;
        ck.src_port = sockets[i].src_port;
        if (inet_pton(AF_INET, sockets[i].end_ip, &ck.dst_ip) != 1) continue;
        ck.dst_port = sockets[i].end_port;
        ck.protocol = 17;

        struct udp_stat val;
        if (bpf_map__lookup_elem(udp_map, &ck, sizeof(ck),
                                 &val, sizeof(val), 0) == 0)
        {
            sockets[i].tx_bytes = val.tx_bytes;
            sockets[i].rx_bytes = val.rx_bytes;
            count++;
        }
    }
    return count;
}

static int aggregate_by_pid(socket_proccess_t *sockets, int n_sockets,
                             proc_agg_t *agg)
{
    int n_agg = 0;
    for (int i = 0; i < n_sockets; i++)
    {
        if (sockets[i].pid[0] == '\0') continue;

        proc_agg_t *p = NULL;
        for (int j = 0; j < n_agg; j++)
        {
            if (strcmp(agg[j].pid, sockets[i].pid) == 0)
            {
                p = &agg[j];
                break;
            }
        }
        if (!p && n_agg < MAX_PROCCESSES)
        {
            p = &agg[n_agg++];
            memset(p, 0, sizeof(proc_agg_t));
            strncpy(p->pid, sockets[i].pid, sizeof(p->pid) - 1);
            strncpy(p->name, sockets[i].name, sizeof(p->name) - 1);
        }
        if (p)
        {
            p->tx_bytes += sockets[i].tx_bytes;
            p->rx_bytes += sockets[i].rx_bytes;
            p->socket_count++;
        }
    }
    return n_agg;
}

static void print_per_process(proc_agg_t *agg, int n_agg,
                               struct proc_prev *prev, int *n_prev,
                               uint64_t now)
{
    for (int i = 0; i < n_agg; i++)
    {
        double tp_sent = 0, tp_recv = 0;
        int found = 0;

        for (int j = 0; j < *n_prev; j++)
        {
            if (strcmp(prev[j].pid, agg[i].pid) == 0)
            {
                uint64_t dt = now - prev[j].timestamp_ns;
                if (dt > 0)
                {
                    tp_sent = (double)(agg[i].tx_bytes - prev[j].tx_bytes) * 1e9 / dt;
                    tp_recv = (double)(agg[i].rx_bytes - prev[j].rx_bytes) * 1e9 / dt;
                }
                prev[j].timestamp_ns = now;
                prev[j].tx_bytes = agg[i].tx_bytes;
                prev[j].rx_bytes = agg[i].rx_bytes;
                found = 1;
                break;
            }
        }

        if (!found && *n_prev < MAX_PROCCESSES)
        {
            strncpy(prev[*n_prev].pid, agg[i].pid, sizeof(prev[*n_prev].pid) - 1);
            prev[*n_prev].timestamp_ns = now;
            prev[*n_prev].tx_bytes = agg[i].tx_bytes;
            prev[*n_prev].rx_bytes = agg[i].rx_bytes;
            (*n_prev)++;
        }

        printf("PID=%s(%s)  TX=%.0f B/s  RX=%.0f B/s  sockets=%d\n",
               agg[i].pid, agg[i].name, tp_sent, tp_recv, agg[i].socket_count);
    }
}

static void print_usage(const char *prog)
{
    fprintf(stderr,
            "Uso: %s [opcoes]\n\n"
            "Opcoes:\n"
            "  -c <path>   Arquivo de regras (default: rules.conf)\n"
            "  -i <name>   Interface de rede (default: detectada)\n"
            "  -h          Mostra esta ajuda\n",
            prog);
}

int main(int argc, char *argv[])
{
    const char *config_path = "rules.conf";
    char *iface = NULL;
    int opt;

    while ((opt = getopt(argc, argv, "c:i:h")) != -1)
    {
        switch (opt)
        {
        case 'c':
            config_path = optarg;
            break;
        case 'i':
            iface = optarg;
            break;
        case 'h':
            print_usage(argv[0]);
            return 0;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }

    if (!iface)
    {
        iface = detect_default_iface();
        if (!iface)
        {
            fprintf(stderr, "Failed to detect default network interface\n");
            return 1;
        }
    }

    struct rtt_bpf *rtt_skel = init_rtt();
    if (!rtt_skel) { free(iface); return 1; }
    if (attach_rtt(rtt_skel)) { cleanup_rtt(rtt_skel); free(iface); return 1; }
    printf("BPF program loaded (RTT)!\n");

    struct cgroup_skb_bpf *cg_skel = init_cgroup_skb_bpf();
    if (!cg_skel)
    {
        cleanup_rtt(rtt_skel);
        free(iface);
        return 1;
    }

    struct speed_estimator est;
    speed_estimator_init(&est, iface);

    struct bpf_map *hists_map = rtt_skel->maps.hists;
    struct bpf_map *udp_map = rtt_skel->maps.udp_hists;
    struct proc_prev *proc_prev = calloc(MAX_PROCCESSES, sizeof(struct proc_prev));
    int n_proc_prev = 0;

    struct rule rules[MAX_RULES];
    int n_rules;

    while (1)
    {
        printf("\n=== Por processo ===\n");

        socket_proccess_t *sockets = malloc(sizeof(socket_proccess_t) * MAX_SOCKETS);
        if (!sockets) break;

        proc_agg_t *agg = calloc(MAX_PROCCESSES, sizeof(proc_agg_t));
        if (!agg) { free(sockets); break; }

        int n_sockets = discover_sockets(sockets, 6);
        int n_tcp = read_socket_data(hists_map, sockets, n_sockets);
        if (n_tcp == 0 && n_sockets > 0)
            fprintf(stderr, "[WARN] 0/%d TCP sockets matched\n", n_sockets);

        int n_udp_raw = discover_sockets(sockets + n_sockets, 17);
        int n_udp = read_udp_socket_data(udp_map, sockets + n_sockets, n_udp_raw);
        if (n_udp == 0 && n_udp_raw > 0)
            fprintf(stderr, "[WARN] 0/%d UDP sockets matched\n", n_udp_raw);

        n_sockets += n_udp_raw;
        int n_agg = aggregate_by_pid(sockets, n_sockets, agg);

        uint64_t now = now_ns();
        speed_estimator_update(&est, now);

        n_rules = parse_rules(config_path, rules, MAX_RULES);
        if (n_rules > 0)
        {
            setup_cgroup_rules(cg_skel, sockets, n_sockets, rules, n_rules);
            free_rules(rules, n_rules);
        }

        print_per_process(agg, n_agg, proc_prev, &n_proc_prev, now);

        free(agg);
        free(sockets);

        printf("=== Capacidade estimada ===\n");
        printf("Capacity: %llu bps  (test=%llu  sysfs=%llu)\n",
               speed_estimator_capacity(&est), est.active_test_bps, est.sysfs_speed_bps);

        sleep(1);
    }

    speed_estimator_destroy(&est);
    free(proc_prev);
    free(iface);
    cleanup_cgroup_skb_bpf(cg_skel);
    cleanup_rtt(rtt_skel);
    return 0;
}