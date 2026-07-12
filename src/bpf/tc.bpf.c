#include "vmlinux.h"
#include "common/monitor.h"
#include <bpf/bpf_helpers.h>

#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct egress_stats);
} egress_map SEC(".maps");

SEC("tc/egress")
int tc_egress(struct __sk_buff *skb) {
    __u32 key = 0;
    struct egress_stats *stats = bpf_map_lookup_elem(&egress_map, &key);
    if (!stats) return TC_ACT_OK;

    __sync_fetch_and_add(&stats->bytes,   skb->len);
    __sync_fetch_and_add(&stats->packets, 1);

    return TC_ACT_OK;
}
