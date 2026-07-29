#ifndef ORCHESTRATOR_H
#define ORCHESTRATOR_H

#include <bpf/libbpf.h>
#include <netinet/in.h>
#include "common/config.h"
#include "common/monitor.h"
#include "net-funcs.h"
#include "xdp.h"
#include "tc.h"

static void clear_bpf_map(struct bpf_map *map, size_t key_size)
{
    char key[64] = {0};
    char next[64] = {0};
    while (bpf_map__get_next_key(map, key, next, key_size) == 0)
    {
        bpf_map__delete_elem(map, next, key_size, 0);
        memcpy(key, next, key_size);
    }
}

void orchestrator_apply(
    const struct rule *rules, int n_rules,
    socket_proccess_t *sockets, int n_sockets,
    struct xdp_bpf *xdp, struct tc_bpf *tc,
    unsigned long long capacity_bps, uint64_t now_ns)
{
    clear_bpf_map(xdp->maps.blocklist_map, sizeof(__u32));
    clear_bpf_map(xdp->maps.ingress_buckets, sizeof(__u32));
    clear_bpf_map(tc->maps.flow_info_map, sizeof(struct flow_key));
    clear_bpf_map(tc->maps.egress_buckets, sizeof(struct flow_key));

    clear_bpf_map(xdp->maps.blocklist_map_v6, sizeof(struct ip_key_v6));
    clear_bpf_map(xdp->maps.ingress_buckets_v6, sizeof(struct ip_key_v6));
    clear_bpf_map(tc->maps.flow_info_map_v6, sizeof(struct flow_key_v6));
    clear_bpf_map(tc->maps.egress_buckets_v6, sizeof(struct flow_key_v6));

    for (int i = 0; i < n_sockets; i++)
    {
        if (sockets[i].pid[0] == '\0')
            continue;

        const struct rule *rule = match_rule(rules, n_rules, sockets[i].name);
        if (!rule)
            continue;

        unsigned int rate_bps = (unsigned int)(capacity_bps * rule->bandwidth_pct / 100);
        struct flow_info fi = {
            .action = rule->action,
            .egress_strategy = rule->egress_strategy,
            .ingress_strategy = rule->ingress_strategy,
            .rate_bps = rate_bps,
        };

        if (sockets[i].family != AF_INET6)
        {
            unsigned int src_ip, dst_ip;
            inet_pton(AF_INET, sockets[i].src_ip, &src_ip);
            inet_pton(AF_INET, sockets[i].end_ip, &dst_ip);

            struct flow_key fk = {
                .src_ip = src_ip,
                .dst_ip = dst_ip,
                .src_port = (unsigned short)sockets[i].src_port,
                .dst_port = (unsigned short)sockets[i].end_port,
                .protocol = sockets[i].protocol,
            };
            bpf_map__update_elem(tc->maps.flow_info_map,
                                 &fk, sizeof(fk), &fi, sizeof(fi), BPF_ANY);

            if (rule->action == ALLOW)
            {
                unsigned int burst = rate_bps / 2;
                struct rate_bucket rb = {
                    .rate_bps = rate_bps,
                    .burst = burst,
                    .tokens = burst,
                    .last_ns = now_ns,
                };
                bpf_map__update_elem(tc->maps.egress_buckets,
                                     &fk, sizeof(fk), &rb, sizeof(rb), BPF_ANY);
            }

            struct block_entry be = {
                .action = rule->action,
                .ingress_strategy = rule->ingress_strategy,
                .rate_bps = rate_bps,
            };
            bpf_map__update_elem(xdp->maps.blocklist_map,
                                 &dst_ip, sizeof(dst_ip), &be, sizeof(be), BPF_ANY);

            if (rule->action == ALLOW)
            {
                unsigned int burst = rate_bps / 2;
                struct rate_bucket rb = {
                    .rate_bps = rate_bps,
                    .burst = burst,
                    .tokens = burst,
                    .last_ns = now_ns,
                };
                bpf_map__update_elem(xdp->maps.ingress_buckets,
                                     &dst_ip, sizeof(dst_ip), &rb, sizeof(rb), BPF_ANY);
            }
        }
        else
        {
            struct in6_addr src_ip6, dst_ip6;
            inet_pton(AF_INET6, sockets[i].src_ip, &src_ip6);
            inet_pton(AF_INET6, sockets[i].end_ip, &dst_ip6);

            struct flow_key_v6 fk6 = {0};
            memcpy(fk6.src_ip, src_ip6.s6_addr, 16);
            memcpy(fk6.dst_ip, dst_ip6.s6_addr, 16);
            fk6.src_port = (unsigned short)sockets[i].src_port;
            fk6.dst_port = (unsigned short)sockets[i].end_port;
            fk6.protocol = sockets[i].protocol;

            bpf_map__update_elem(tc->maps.flow_info_map_v6,
                                 &fk6, sizeof(fk6), &fi, sizeof(fi), BPF_ANY);

            if (rule->action == ALLOW)
            {
                unsigned int burst = rate_bps / 2;
                struct rate_bucket rb = {
                    .rate_bps = rate_bps,
                    .burst = burst,
                    .tokens = burst,
                    .last_ns = now_ns,
                };
                bpf_map__update_elem(tc->maps.egress_buckets_v6,
                                     &fk6, sizeof(fk6), &rb, sizeof(rb), BPF_ANY);
            }

            struct block_entry be = {
                .action = rule->action,
                .ingress_strategy = rule->ingress_strategy,
                .rate_bps = rate_bps,
            };
            struct ip_key_v6 ik6;
            memcpy(ik6.addr, dst_ip6.s6_addr, 16);
            bpf_map__update_elem(xdp->maps.blocklist_map_v6,
                                 &ik6, sizeof(ik6), &be, sizeof(be), BPF_ANY);

            if (rule->action == ALLOW)
            {
                unsigned int burst = rate_bps / 2;
                struct rate_bucket rb = {
                    .rate_bps = rate_bps,
                    .burst = burst,
                    .tokens = burst,
                    .last_ns = now_ns,
                };
                bpf_map__update_elem(xdp->maps.ingress_buckets_v6,
                                     &ik6, sizeof(ik6), &rb, sizeof(rb), BPF_ANY);
            }
        }
    }
}

void orchestrator_cleanup_maps(struct xdp_bpf *xdp, struct tc_bpf *tc)
{
    clear_bpf_map(xdp->maps.blocklist_map, sizeof(__u32));
    clear_bpf_map(xdp->maps.ingress_buckets, sizeof(__u32));
    clear_bpf_map(tc->maps.flow_info_map, sizeof(struct flow_key));
    clear_bpf_map(tc->maps.egress_buckets, sizeof(struct flow_key));

    clear_bpf_map(xdp->maps.blocklist_map_v6, sizeof(struct ip_key_v6));
    clear_bpf_map(xdp->maps.ingress_buckets_v6, sizeof(struct ip_key_v6));
    clear_bpf_map(tc->maps.flow_info_map_v6, sizeof(struct flow_key_v6));
    clear_bpf_map(tc->maps.egress_buckets_v6, sizeof(struct flow_key_v6));
}

#endif
