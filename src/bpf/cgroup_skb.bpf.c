#include "vmlinux.h"
#include "common/monitor.h"
#include "bpf_common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct egress_stats);
} cg_egress_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ingress_stats);
} cg_ingress_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u64);
    __type(value, struct flow_info);
} cgroup_rule_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u64);
    __type(value, struct rate_bucket);
} cg_egress_buckets SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u64);
    __type(value, struct rate_bucket);
} cg_ingress_buckets SEC(".maps");

SEC("cgroup_skb/egress")
int cg_egress(struct __sk_buff *skb)
{
    __u64 cgid = bpf_skb_cgroup_id(skb);
    if (!cgid) return 1;

    __u32 zero = 0;
    struct egress_stats *stats = bpf_map_lookup_elem(&cg_egress_stats, &zero);
    if (stats) {
        __sync_fetch_and_add(&stats->bytes, skb->len);
        __sync_fetch_and_add(&stats->packets, 1);
    }

    struct flow_info *info = bpf_map_lookup_elem(&cgroup_rule_map, &cgid);
    if (!info) return 1;

    if (info->action == BLOCK) return 0;

    struct rate_bucket *bucket = bpf_map_lookup_elem(&cg_egress_buckets, &cgid);
    if (!bucket) return 1;

    refill_bucket(bucket);
    if (bucket->tokens >= skb->len) {
        __sync_fetch_and_sub(&bucket->tokens, skb->len);
        return 1;
    }

    if (info->egress_strategy == STRATEGY_DROP) return 0;

    return 1;
}

SEC("cgroup_skb/ingress")
int cg_ingress(struct __sk_buff *skb)
{
    __u64 cgid = bpf_skb_cgroup_id(skb);
    if (!cgid) return 1;

    __u32 zero = 0;
    struct ingress_stats *stats = bpf_map_lookup_elem(&cg_ingress_stats, &zero);
    if (stats) {
        __sync_fetch_and_add(&stats->bytes, skb->len);
        __sync_fetch_and_add(&stats->packets, 1);
    }

    struct flow_info *info = bpf_map_lookup_elem(&cgroup_rule_map, &cgid);
    if (!info) return 1;

    if (info->action == BLOCK) return 0;

    struct rate_bucket *bucket = bpf_map_lookup_elem(&cg_ingress_buckets, &cgid);
    if (!bucket) return 1;

    refill_bucket(bucket);
    if (bucket->tokens >= skb->len) {
        __sync_fetch_and_sub(&bucket->tokens, skb->len);
        return 1;
    }

    if (info->ingress_strategy == STRATEGY_DROP) return 0;

    return 1;
}