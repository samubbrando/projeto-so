#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <arpa/inet.h>
#include "hist.h"
#include "netlink-funcs.h"
#include "rtt.h"

struct proc_prev {
    char pid[16];
    uint64_t timestamp_ns;
    unsigned long long tx_bytes;
    unsigned long long rx_bytes;
};

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

int main() {
    struct rtt_bpf *skel = init_bpf();
    if (!skel) return 1;

    if (attach_bpf(skel)) {
        cleanup_bpf(skel);
        return 1;
    }

    struct bpf_map *hists_map = skel->maps.hists;
    struct proc_prev *proc_prev = calloc(MAX_PROCCESSES, sizeof(struct proc_prev));
    int n_proc_prev = 0;

    while (1) {
        socket_proccess_t *sockets = malloc(sizeof(socket_proccess_t) * MAX_SOCKETS);
        if (!sockets) {
            perror("Error allocating memory for socket-proccess array\n");
            break;
        }
        int n_sockets = discover_sockets(sockets);

        for (int i = 0; i < n_sockets; i++) {
            if (sockets[i].pid[0] == '\0') continue;

            struct conn_key ck;
            inet_pton(AF_INET, sockets[i].src_ip, &ck.src_ip);
            ck.src_port = sockets[i].src_port;
            inet_pton(AF_INET, sockets[i].end_ip, &ck.dst_ip);
            ck.dst_port = sockets[i].end_port;

            struct hist val;
            if (bpf_map__lookup_elem(hists_map, &ck, sizeof(ck), &val, sizeof(val), 0) == 0) {
                sockets[i].tx_bytes = val.sent;
                sockets[i].rx_bytes = val.received;
                sockets[i].rtt = val.rtt;
            }
        }

        proc_agg_t *agg = calloc(MAX_PROCCESSES, sizeof(proc_agg_t));
        int n_agg = 0;

        for (int i = 0; i < n_sockets; i++) {
            if (sockets[i].pid[0] == '\0') continue;

            proc_agg_t *p = NULL;
            for (int j = 0; j < n_agg; j++) {
                if (strcmp(agg[j].pid, sockets[i].pid) == 0) {
                    p = &agg[j];
                    break;
                }
            }
            if (!p && n_agg < MAX_PROCCESSES) {
                p = &agg[n_agg++];
                memset(p, 0, sizeof(proc_agg_t));
                strncpy(p->pid, sockets[i].pid, sizeof(p->pid) - 1);
                strncpy(p->name, sockets[i].name, sizeof(p->name) - 1);
            }
            if (p) {
                p->tx_bytes += sockets[i].tx_bytes;
                p->rx_bytes += sockets[i].rx_bytes;
                p->socket_count++;
            }
        }

        uint64_t now = now_ns();
        for (int i = 0; i < n_agg; i++) {
            double tp_sent = 0, tp_recv = 0;
            int found = 0;

            for (int j = 0; j < n_proc_prev; j++) {
                if (strcmp(proc_prev[j].pid, agg[i].pid) == 0) {
                    uint64_t dt = now - proc_prev[j].timestamp_ns;
                    if (dt > 0) {
                        tp_sent = (double)(agg[i].tx_bytes - proc_prev[j].tx_bytes) * 1e9 / dt;
                        tp_recv = (double)(agg[i].rx_bytes - proc_prev[j].rx_bytes) * 1e9 / dt;
                    }
                    proc_prev[j].timestamp_ns = now;
                    proc_prev[j].tx_bytes = agg[i].tx_bytes;
                    proc_prev[j].rx_bytes = agg[i].rx_bytes;
                    found = 1;
                    break;
                }
            }

            if (!found && n_proc_prev < MAX_PROCCESSES) {
                strncpy(proc_prev[n_proc_prev].pid, agg[i].pid, sizeof(proc_prev[n_proc_prev].pid) - 1);
                proc_prev[n_proc_prev].timestamp_ns = now;
                proc_prev[n_proc_prev].tx_bytes = agg[i].tx_bytes;
                proc_prev[n_proc_prev].rx_bytes = agg[i].rx_bytes;
                n_proc_prev++;
            }

            printf("PID=%s(%s)  TX=%.0f B/s  RX=%.0f B/s  sockets=%d\n",
                   agg[i].pid, agg[i].name, tp_sent, tp_recv, agg[i].socket_count);
        }

        free(agg);
        free(sockets);
        sleep(1);
    }

    free(proc_prev);
    cleanup_bpf(skel);
    return 0;
}
