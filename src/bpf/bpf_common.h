#ifndef BPF_COMMON_H
#define BPF_COMMON_H

#include "vmlinux.h"
#include "common/monitor.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

static __always_inline void refill_bucket(struct rate_bucket *bucket)
{
    if (bucket->rate_bps == 0)
        return;
    __u64 now = bpf_ktime_get_ns();
    __u64 elapsed = now - bucket->last_ns;
    __u64 max_elapsed = ~0ULL / bucket->rate_bps;
    if (elapsed > max_elapsed)
        elapsed = max_elapsed;
    __u64 added = (bucket->rate_bps * elapsed) / 8000000000ULL;
    bucket->tokens += added;
    if (bucket->tokens > bucket->burst)
        bucket->tokens = bucket->burst;
    bucket->last_ns = now;
}

static __always_inline int parse_transport(void *data, void *data_end,
                                            struct flow_key *key,
                                            struct flow_key_v6 *key6,
                                            int is_v6)
{
    struct tcphdr *tcph = data;
    if ((void *)(tcph + 1) > data_end)
        return 0;
    unsigned short src = bpf_ntohs(tcph->source);
    unsigned short dst = bpf_ntohs(tcph->dest);
    if (is_v6) {
        key6->src_port = src;
        key6->dst_port = dst;
    } else {
        key->src_port = src;
        key->dst_port = dst;
    }
    return 1;
}

static __always_inline int parse_udp(void *data, void *data_end,
                                      struct flow_key *key,
                                      struct flow_key_v6 *key6,
                                      int is_v6)
{
    struct udphdr *udph = data;
    if ((void *)(udph + 1) > data_end)
        return 0;
    unsigned short src = bpf_ntohs(udph->source);
    unsigned short dst = bpf_ntohs(udph->dest);
    if (is_v6) {
        key6->src_port = src;
        key6->dst_port = dst;
    } else {
        key->src_port = src;
        key->dst_port = dst;
    }
    return 1;
}


#endif
