#ifndef ORCHESTRATOR_H
#define ORCHESTRATOR_H

#include <bpf/libbpf.h>
#include <netinet/in.h>
#include "common/config.h"
#include "common/monitor.h"
#include "net-funcs.h"
#include "xdp.h"
#include "tc.h"

#define BURST_SECONDS 1

static struct flow_key prev_fk[MAX_SOCKETS], cur_fk[MAX_SOCKETS];
static int n_prev_fk, n_cur_fk;

static struct flow_key_v6 prev_fk6[MAX_SOCKETS], cur_fk6[MAX_SOCKETS];
static int n_prev_fk6, n_cur_fk6;

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

void delete_index_v6(struct xdp_bpf *xdp, struct tc_bpf *tc, int index)
{
    bpf_map__delete_elem(xdp->maps.blocklist_map_v6, &prev_fk6[index], sizeof(struct flow_key_v6), 0);
    bpf_map__delete_elem(xdp->maps.ingress_buckets_v6, &prev_fk6[index], sizeof(struct flow_key_v6), 0);
    bpf_map__delete_elem(tc->maps.flow_info_map_v6, &prev_fk6[index], sizeof(struct flow_key_v6), 0);
    bpf_map__delete_elem(tc->maps.egress_buckets_v6, &prev_fk6[index], sizeof(struct flow_key_v6), 0);
}

void delete_index_v4(struct xdp_bpf *xdp, struct tc_bpf *tc, int index)
{
    bpf_map__delete_elem(xdp->maps.blocklist_map, &prev_fk[index], sizeof(struct flow_key), 0);
    bpf_map__delete_elem(xdp->maps.ingress_buckets, &prev_fk[index], sizeof(struct flow_key), 0);
    bpf_map__delete_elem(tc->maps.flow_info_map, &prev_fk[index], sizeof(struct flow_key), 0);
    bpf_map__delete_elem(tc->maps.egress_buckets, &prev_fk[index], sizeof(struct flow_key), 0);
}

void cleanup_key_v4(struct xdp_bpf *xdp, struct tc_bpf *tc)
{
    for (int i = 0; i < n_prev_fk; i++)
    {
        int found = 0;
        for (int j = 0; j < n_cur_fk; j++)
        {
            if (memcmp(&prev_fk[i], &cur_fk[j], sizeof(struct flow_key)) == 0)
            {
                found = 1;
                break;
            }
        }

        if (!found)
            delete_index_v4(xdp, tc, i);
    }
}

void cleanup_key_v6(struct xdp_bpf *xdp, struct tc_bpf *tc)
{
    for (int i = 0; i < n_prev_fk6; i++)
    {
        int found = 0;
        for (int j = 0; j < n_cur_fk6; j++)
        {
            if (memcmp(&prev_fk6[i], &cur_fk6[j], sizeof(struct flow_key_v6)) == 0)
            {
                found = 1;
                break;
            }
        }

        if (!found)
            delete_index_v6(xdp, tc, i);
    }
}

static void update_rate_bucket(struct bpf_map *map, const void *key, size_t key_size,
                               unsigned long long rate_bps, unsigned long long burst,
                               uint64_t now_ns)
{
    struct rate_bucket rb;
    if (bpf_map__lookup_elem(map, key, key_size, &rb, sizeof(rb), 0) != 0)
    {
        memset(&rb, 0, sizeof(rb));
        rb.tokens = burst;
        rb.last_ns = now_ns;
    }
    else
    {
        if (rb.rate_bps != rate_bps)
            rb.last_ns = now_ns;
        if (rb.tokens > burst)
            rb.tokens = burst;
    }
    rb.rate_bps = rate_bps;
    rb.burst = burst;
    bpf_map__update_elem(map, key, key_size, &rb, sizeof(rb), BPF_ANY);
}

void orchestrator_apply(
    const struct rule *rules, int n_rules,
    socket_proccess_t *sockets, int n_sockets,
    struct xdp_bpf *xdp, struct tc_bpf *tc,
    unsigned long long capacity_bps, uint64_t now_ns)
{
    n_cur_fk = 0;
    n_cur_fk6 = 0;

    for (int i = 0; i < n_sockets; i++)
    {
        if (sockets[i].pid[0] == '\0')
            continue;

        const struct rule *rule = match_rule(rules, n_rules, sockets[i].name);
        if (!rule)
            continue;

        unsigned long long rate_bps = capacity_bps * rule->bandwidth_pct / 100;
        struct flow_info fi = {
            .action = rule->action,
            .egress_strategy = rule->egress_strategy,
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

            if (n_cur_fk < MAX_SOCKETS)
                cur_fk[n_cur_fk++] = fk;

            bpf_map__update_elem(tc->maps.flow_info_map,
                                 &fk, sizeof(fk), &fi, sizeof(fi), BPF_ANY);

            if (rule->action == ALLOW)
            {
                unsigned long long burst = rate_bps / 8;
                update_rate_bucket(tc->maps.egress_buckets, &fk, sizeof(fk),
                                   rate_bps, burst, now_ns);
                update_rate_bucket(xdp->maps.ingress_buckets, &fk, sizeof(fk),
                                   rate_bps, burst, now_ns);
            }

            struct block_entry be = {
                .action = rule->action,
                .ingress_strategy = rule->ingress_strategy,
                .rate_bps = rate_bps,
            };
            bpf_map__update_elem(xdp->maps.blocklist_map,
                                 &fk, sizeof(fk), &be, sizeof(be), BPF_ANY);
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

            if (n_cur_fk6 < MAX_SOCKETS)
                cur_fk6[n_cur_fk6++] = fk6;

            bpf_map__update_elem(tc->maps.flow_info_map_v6,
                                 &fk6, sizeof(fk6), &fi, sizeof(fi), BPF_ANY);

            if (rule->action == ALLOW)
            {
                unsigned long long burst = rate_bps / 8 / 2;
                update_rate_bucket(tc->maps.egress_buckets_v6, &fk6, sizeof(fk6),
                                   rate_bps, burst, now_ns);
                update_rate_bucket(xdp->maps.ingress_buckets_v6, &fk6, sizeof(fk6),
                                   rate_bps, burst, now_ns);
            }

            struct block_entry be = {
                .action = rule->action,
                .ingress_strategy = rule->ingress_strategy,
                .rate_bps = rate_bps,
            };
            bpf_map__update_elem(xdp->maps.blocklist_map_v6,
                                 &fk6, sizeof(fk6), &be, sizeof(be), BPF_ANY);
        }
    }

    cleanup_key_v4(xdp, tc);
    cleanup_key_v6(xdp, tc);

    memcpy(prev_fk, cur_fk, sizeof(struct flow_key) * n_cur_fk);
    n_prev_fk = n_cur_fk;
    n_cur_fk = 0;

    memcpy(prev_fk6, cur_fk6, sizeof(struct flow_key_v6) * n_cur_fk6);
    n_prev_fk6 = n_cur_fk6;
    n_cur_fk6 = 0;
}

void orchestrator_cleanup_maps(struct xdp_bpf *xdp, struct tc_bpf *tc)
{
    clear_bpf_map(xdp->maps.blocklist_map, sizeof(struct flow_key));
    clear_bpf_map(xdp->maps.ingress_buckets, sizeof(struct flow_key));
    clear_bpf_map(tc->maps.flow_info_map, sizeof(struct flow_key));
    clear_bpf_map(tc->maps.egress_buckets, sizeof(struct flow_key));

    clear_bpf_map(xdp->maps.blocklist_map_v6, sizeof(struct flow_key_v6));
    clear_bpf_map(xdp->maps.ingress_buckets_v6, sizeof(struct flow_key_v6));
    clear_bpf_map(tc->maps.flow_info_map_v6, sizeof(struct flow_key_v6));
    clear_bpf_map(tc->maps.egress_buckets_v6, sizeof(struct flow_key_v6));
}

#endif
