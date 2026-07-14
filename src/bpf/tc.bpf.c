#include "vmlinux.h"
#include "common/monitor.h"
#include "bpf_common.h"
#include <bpf/bpf_helpers.h>

#define TC_ACT_OK 0
#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct egress_stats);
} egress_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct flow_key);
    __type(value, struct flow_info);
} flow_info_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct flow_key);
    __type(value, struct rate_bucket);
    
} egress_buckets SEC(".maps");
SEC("tc/egress")
int tc_egress(struct __sk_buff *skb) {
    __u32 key = 0;
    struct egress_stats *stats = bpf_map_lookup_elem(&egress_map, &key);
    if (!stats) return TC_ACT_OK;

    __sync_fetch_and_add(&stats->bytes,   skb->len);
    __sync_fetch_and_add(&stats->packets, 1);

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *ethdr = data;
    if ((void *)(ethdr + 1) > data_end) return TC_ACT_OK;
    if (bpf_ntohs(ethdr->h_proto) != ETH_P_IP) return TC_ACT_OK;

    struct iphdr *iph = data + sizeof(struct ethhdr);
    if ((void *)(iph + 1) > data_end) return TC_ACT_OK;
    if (iph->protocol != IPPROTO_TCP) return TC_ACT_OK;
    struct tcphdr *tcph = data + sizeof(struct ethhdr) + (iph->ihl * 4);
    
    if ((void *)(tcph + 1) > data_end) return TC_ACT_OK;

    return TC_ACT_OK;
}
