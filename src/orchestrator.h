#ifndef ORCHESTRATOR_H
#define ORCHESTRATOR_H

#include <bpf/libbpf.h>
#include <netinet/in.h>
#include "common/config.h"
#include "common/monitor.h"
#include "net-funcs.h"
#include "xdp.h"
#include "tc.h"

#define BURST_SECONDS 0.1

static struct flow_key prev_fk[MAX_SOCKETS], cur_fk[MAX_SOCKETS];
static int n_prev_fk, n_cur_fk;

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

static void delete_flow(struct xdp_bpf *xdp, struct tc_bpf *tc, int index)
{
    bpf_map__delete_elem(xdp->maps.flow_map, &prev_fk[index], sizeof(struct flow_key), 0);
    bpf_map__delete_elem(xdp->maps.ingress_buckets, &prev_fk[index], sizeof(struct flow_key), 0);
    bpf_map__delete_elem(tc->maps.flow_map, &prev_fk[index], sizeof(struct flow_key), 0);
    bpf_map__delete_elem(tc->maps.egress_buckets, &prev_fk[index], sizeof(struct flow_key), 0);
}

static void cleanup_stale_flows(struct xdp_bpf *xdp, struct tc_bpf *tc)
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
            delete_flow(xdp, tc, i);
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

static struct flow_key make_flow_key(const socket_proccess_t *s)
{
    struct flow_key fk = {0};
    fk.src_port = (unsigned short)s->src_port;
    fk.dst_port = (unsigned short)s->end_port;
    fk.protocol = (unsigned char)s->protocol;

    if (s->family != AF_INET6)
    {
        unsigned int src_ip, dst_ip;
        inet_pton(AF_INET, s->src_ip, &src_ip);
        inet_pton(AF_INET, s->end_ip, &dst_ip);
        fk.family = FLOW_FAMILY_IPV4;
        fk.addr.ip4[0] = src_ip;
        fk.addr.ip4[1] = dst_ip;
    }
    else
    {
        struct in6_addr src_ip6, dst_ip6;
        inet_pton(AF_INET6, s->src_ip, &src_ip6);
        inet_pton(AF_INET6, s->end_ip, &dst_ip6);
        fk.family = FLOW_FAMILY_IPV6;
        memcpy(fk.addr.ip6, src_ip6.s6_addr, 16);
        memcpy(fk.addr.ip6 + 16, dst_ip6.s6_addr, 16);
    }
    return fk;
}

void orchestrator_apply(
    const struct rule *rules, int n_rules,
    socket_proccess_t *sockets, int n_sockets,
    struct xdp_bpf *xdp, struct tc_bpf *tc,
    unsigned long long capacity_bps, uint64_t now_ns)
{
    n_cur_fk = 0;

    for (int i = 0; i < n_sockets; i++)
    {
        if (sockets[i].pid[0] == '\0')
            continue;

        const struct rule *rule = match_rule(rules, n_rules, sockets[i].name);
        if (!rule)
            continue;

        unsigned long long rate_bps = capacity_bps * rule->bandwidth_pct / 100;
        struct flow_key fk = make_flow_key(&sockets[i]);

        if (n_cur_fk < MAX_SOCKETS)
            cur_fk[n_cur_fk++] = fk;
        
        struct flow_policy egress = {
            .action = rule->action,
            .strategy = rule->egress_strategy,
            .rate_bps = rate_bps,
        };
        bpf_map__update_elem(tc->maps.flow_map,
                             &fk, sizeof(fk), &egress, sizeof(egress), BPF_ANY);

        struct flow_policy ingress = {
            .action = rule->action,
            .strategy = rule->ingress_strategy,
            .rate_bps = rate_bps,
        };
        bpf_map__update_elem(xdp->maps.flow_map,
                             &fk, sizeof(fk), &ingress, sizeof(ingress), BPF_ANY);

        if (rule->action == ALLOW)
        {
            unsigned long long burst = rate_bps / 8;
            burst = burst / (1 / BURST_SECONDS);
            
            if (sockets[i].family == AF_INET6)
                burst /= 2;

            update_rate_bucket(tc->maps.egress_buckets, &fk, sizeof(fk),
                               rate_bps, burst, now_ns);
            update_rate_bucket(xdp->maps.ingress_buckets, &fk, sizeof(fk),
                               rate_bps, burst, now_ns);
        }
    }

    cleanup_stale_flows(xdp, tc);

    memcpy(prev_fk, cur_fk, sizeof(struct flow_key) * n_cur_fk);
    n_prev_fk = n_cur_fk;
    n_cur_fk = 0;
}

void orchestrator_cleanup_maps(struct xdp_bpf *xdp, struct tc_bpf *tc)
{
    clear_bpf_map(xdp->maps.flow_map, sizeof(struct flow_key));
    clear_bpf_map(xdp->maps.ingress_buckets, sizeof(struct flow_key));
    clear_bpf_map(tc->maps.flow_map, sizeof(struct flow_key));
    clear_bpf_map(tc->maps.egress_buckets, sizeof(struct flow_key));
}

#endif
