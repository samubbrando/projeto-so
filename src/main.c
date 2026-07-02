#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <arpa/inet.h>
#include "hist.h"
#include "netlink-funcs.h"
#include "rtt.h"

#define MAX_ENTRIES 4096

struct prev_reading {
    uint64_t timestamp_ns;
    uint64_t sent;
    uint64_t received;
};

struct conn_key_prev {
    struct conn_key key;
    struct prev_reading reading;
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
    struct conn_key_prev prev[MAX_ENTRIES];
    int n_prev = 0;

    while (1) {
        socket_proccess_t *sockets = malloc(sizeof(socket_proccess_t) * MAX_SOCKETS);
        if (!sockets) { 
            perror("Error allocating memory for socket-proccess array\n"); 
            break; 
        }
        int n_sockets = discover_sockets(sockets);

        struct conn_key key = {}, next;
        int first = 1;

        while (bpf_map__get_next_key(
                   hists_map,
                   first ? NULL : &key,
                   &next, sizeof(next)) == 0)
        {
            struct hist value;
            if (bpf_map__lookup_elem(hists_map, &next, sizeof(next),
                                     &value, sizeof(value), 0) < 0)
                goto next_key;

            char src_str[INET_ADDRSTRLEN], dst_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &next.src_ip, src_str, sizeof(src_str));
            inet_ntop(AF_INET, &next.dst_ip, dst_str, sizeof(dst_str));

            char *pid = "-", *name = "-";
            for (int j = 0; j < n_sockets; j++) {
                if (strcmp(sockets[j].src_ip, src_str) == 0 &&
                    sockets[j].src_port == next.src_port &&
                    strcmp(sockets[j].end_ip, dst_str) == 0 &&
                    sockets[j].end_port == next.dst_port) {
                    pid = sockets[j].pid;
                    name = sockets[j].name;
                    break;
                }
            }

            uint64_t now = now_ns();
            double tp_sent = 0, tp_recv = 0;
            int found = 0;

            for (int j = 0; j < n_prev; j++) {
                if (memcmp(&prev[j].key, &next, sizeof(struct conn_key)) == 0) {
                    uint64_t dt = now - prev[j].reading.timestamp_ns;
                    if (dt > 0) {
                        tp_sent = (double)(value.sent - prev[j].reading.sent) * 1e9 / dt;
                        tp_recv = (double)(value.received - prev[j].reading.received) * 1e9 / dt;
                    }
                    prev[j].reading.timestamp_ns = now;
                    prev[j].reading.sent = value.sent;
                    prev[j].reading.received = value.received;
                    found = 1;
                    break;
                }
            }

            if (!found && n_prev < MAX_ENTRIES) {
                prev[n_prev].key = next;
                prev[n_prev].reading.timestamp_ns = now;
                prev[n_prev].reading.sent = value.sent;
                prev[n_prev].reading.received = value.received;
                n_prev++;
            }

            printf("%s:%u -> %s:%u  RTT=%uus  TX=%.0f B/s  RX=%.0f B/s  PID=%s(%s)\n",
                   src_str, next.src_port, dst_str, next.dst_port,
                   value.rtt, tp_sent, tp_recv, pid, name);
next_key:
            key = next;
            first = 0;
        }

        free(sockets);
        sleep(1);
    }

    cleanup_bpf(skel);
    return 0;
}
