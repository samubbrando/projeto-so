#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "common/hist.h"
#include "common/config.h"
#include "net-funcs.h"
#include "rtt.h"
#include "xdp.h"
#include "tc.h"
#include "speed_estimator.h"
#include "orchestrator.h"

#define MAX_RULES 256

static struct tc_bpf *g_tc_skel;

static unsigned long long read_egress_bytes(void)
{
    if (!g_tc_skel)
        return 0;
    struct egress_stats s = {0};
    read_tc_egress(g_tc_skel, &s);
    return s.bytes;
}

struct proc_prev
{
    char pid[16];
    uint64_t timestamp_ns;
    unsigned long long tx_bytes;
    unsigned long long rx_bytes;
};

struct global_prev
{
    uint64_t timestamp_ns;
    unsigned long long rx_bytes;
    unsigned long long tx_bytes;
    unsigned long long sum_rx;
    unsigned long long sum_tx;
};

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static int init_bpf_modules(struct xdp_bpf **xdp, struct tc_bpf **tc,
                            struct rtt_bpf **rtt, char *iface)
{
    *xdp = init_xdp();
    if (!*xdp)
        return 1;
    if (attach_xdp(*xdp, iface))
    {
        cleanup_xdp(*xdp);
        return 1;
    }

    *tc = init_tc();
    if (!*tc)
        return 1;
    if (attach_tc_egress(*tc, iface))
    {
        cleanup_tc(*tc);
        return 1;
    }

    *rtt = init_rtt();
    if (!*rtt)
        return 1;
    if (attach_rtt(*rtt))
    {
        cleanup_rtt(*rtt);
        return 1;
    }

    return 0;
}

static void cleanup_bpf_modules(struct xdp_bpf *xdp, struct tc_bpf *tc,
                                struct rtt_bpf *rtt)
{
    if (rtt)
        cleanup_rtt(rtt);
    if (tc)
        cleanup_tc(tc);
    if (xdp)
        cleanup_xdp(xdp);
}

static int read_socket_data(struct bpf_map *hists_map,
                            socket_proccess_t *sockets, int n_sockets)
{
    int count = 0;
    for (int i = 0; i < n_sockets; i++)
    {
        if (sockets[i].pid[0] == '\0')
            continue;

        struct conn_key ck;
        inet_pton(AF_INET, sockets[i].src_ip, &ck.src_ip);
        ck.src_port = sockets[i].src_port;
        inet_pton(AF_INET, sockets[i].end_ip, &ck.dst_ip);
        ck.dst_port = sockets[i].end_port;

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

static int aggregate_by_pid(socket_proccess_t *sockets, int n_sockets,
                            proc_agg_t *agg)
{
    int n_agg = 0;
    for (int i = 0; i < n_sockets; i++)
    {
        if (sockets[i].pid[0] == '\0')
            continue;

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

static void sum_per_process(proc_agg_t *agg, int n_agg,
                            unsigned long long *out_sum_tx,
                            unsigned long long *out_sum_rx)
{
    *out_sum_tx = 0;
    *out_sum_rx = 0;
    for (int i = 0; i < n_agg; i++)
    {
        *out_sum_tx += agg[i].tx_bytes;
        *out_sum_rx += agg[i].rx_bytes;
    }
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

static void print_global_interface(const char *iface,
                                   struct xdp_bpf *xdp,
                                   struct tc_bpf *tc,
                                   struct ingress_stats *ingress,
                                   struct egress_stats *egress,
                                   struct global_prev *g_prev,
                                   uint64_t now,
                                   unsigned long long sum_tx,
                                   unsigned long long sum_rx)
{
    read_xdp_ingress(xdp, ingress);
    read_tc_egress(tc, egress);

    printf("=== Interface [%s] ===\n", iface);

    if (g_prev->timestamp_ns != 0)
    {
        uint64_t dt = now - g_prev->timestamp_ns;
        if (dt > 0)
        {
            unsigned long long rx_global_delta = ingress->bytes - g_prev->rx_bytes;
            unsigned long long tx_global_delta = egress->bytes - g_prev->tx_bytes;
            unsigned long long rx_proc_delta = sum_rx - g_prev->sum_rx;
            unsigned long long tx_proc_delta = sum_tx - g_prev->sum_tx;

            double rx_bps = (double)rx_global_delta * 1e9 / dt;
            double tx_bps = (double)tx_global_delta * 1e9 / dt;

            printf("RX: %.0f B/s  TX: %.0f B/s\n", rx_bps, tx_bps);

            if (rx_global_delta > 0)
            {
                double rx_pct = 100.0 * (double)rx_proc_delta / rx_global_delta;
                if (rx_pct < 50.0 || rx_pct > 150.0)
                    printf("[ALERTA] RX: apenas %.0f%% contabilizado por processos\n", rx_pct);
            }
            if (tx_global_delta > 0)
            {
                double tx_pct = 100.0 * (double)tx_proc_delta / tx_global_delta;
                if (tx_pct < 50.0 || tx_pct > 150.0)
                    printf("[ALERTA] TX: apenas %.0f%% contabilizado por processos\n", tx_pct);
            }
        }
    }
    else
    {
        printf("(coletando baseline...)\n");
    }

    g_prev->timestamp_ns = now;
    g_prev->rx_bytes = ingress->bytes;
    g_prev->tx_bytes = egress->bytes;
    g_prev->sum_rx = sum_rx;
    g_prev->sum_tx = sum_tx;
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

    struct xdp_bpf *xdp_skel;
    struct tc_bpf *tc_skel;
    struct rtt_bpf *rtt_skel;

    if (init_bpf_modules(&xdp_skel, &tc_skel, &rtt_skel, iface))
    {
        if (iface)
            free(iface);
        return 1;
    }

    g_tc_skel = tc_skel;

    struct rule rules[MAX_RULES];
    int n_rules = parse_rules(config_path, rules, MAX_RULES);
    if (n_rules < 0)
        n_rules = 0;
    printf("Loaded %d rules from %s\n", n_rules, config_path);

    struct speed_estimator est;
    speed_estimator_init(&est, iface);

    struct bpf_map *hists_map = rtt_skel->maps.hists;
    struct proc_prev *proc_prev = calloc(MAX_PROCCESSES, sizeof(struct proc_prev));
    struct ingress_stats ingress = {0};
    struct egress_stats egress = {0};
    struct global_prev g_prev = {0};
    int n_proc_prev = 0;

    while (1)
    {
        socket_proccess_t *sockets = malloc(sizeof(socket_proccess_t) * MAX_SOCKETS);
        if (!sockets)
            break;

        proc_agg_t *agg = calloc(MAX_PROCCESSES, sizeof(proc_agg_t));
        if (!agg)
        {
            free(sockets);
            break;
        }

        int n_sockets = discover_sockets(sockets);

        uint64_t now = now_ns();
        speed_estimator_update(&est, read_egress_bytes, now);

        orchestrator_apply(rules, n_rules, sockets, n_sockets,
                           xdp_skel, tc_skel,
                           speed_estimator_capacity(&est), now);

        read_socket_data(hists_map, sockets, n_sockets);
        int n_agg = aggregate_by_pid(sockets, n_sockets, agg);

        unsigned long long sum_tx, sum_rx;
        sum_per_process(agg, n_agg, &sum_tx, &sum_rx);

        printf("\n=== Por processo ===\n");
        print_per_process(agg, n_agg, proc_prev, &n_proc_prev, now);

        free(agg);
        free(sockets);

        print_global_interface(iface, xdp_skel, tc_skel,
                               &ingress, &egress, &g_prev,
                               now, sum_tx, sum_rx);

        unsigned long long cap = speed_estimator_capacity(&est);
        printf("=== Capacidade estimada ===\n");
        printf("Capacity: %llu bps  (test=%llu  sysfs=%llu)\n",
               cap, est.active_test_bps, est.sysfs_speed_bps);

        sleep(1);
    }

    orchestrator_cleanup_maps(xdp_skel, tc_skel);
    speed_estimator_destroy(&est);
    free_rules(rules, n_rules);
    free(proc_prev);
    if (iface)
        free(iface);
    cleanup_bpf_modules(xdp_skel, tc_skel, rtt_skel);
    return 0;
}
