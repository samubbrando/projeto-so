#include "vmlinux.h"
#include "common/monitor.h"
#include "bpf_common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define XDP_LOG(fmt, ...) bpf_printk("XDP: " fmt, ##__VA_ARGS__)

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct traffic_stats);
} ingress_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct flow_key);
    __type(value, struct flow_policy);
} flow_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct flow_key);
    __type(value, struct rate_bucket);
} ingress_buckets SEC(".maps");

SEC("xdp")
int xdp_ingress(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 size = (__u32)(data_end - data);

    __u32 stats_key = 0;
    struct traffic_stats *stats = bpf_map_lookup_elem(&ingress_map, &stats_key);
    if (!stats)
    {
        XDP_LOG("missing ingress stats");
        return XDP_PASS;
    }
    __sync_fetch_and_add(&stats->packets, 1);
    __sync_fetch_and_add(&stats->bytes, size);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
    {
        XDP_LOG("ethernet header truncated");
        return XDP_PASS;
    }

    unsigned short h_proto = bpf_ntohs(eth->h_proto);
    if (h_proto != ETH_P_IP && h_proto != ETH_P_IPV6)
    {
        XDP_LOG("unsupported ether h_proto=%u, scheduler only supports %u %u", h_proto, ETH_P_IP, ETH_P_IPV6);
        return XDP_PASS;
    }

    void *l3 = data + sizeof(struct ethhdr);
    struct flow_key key = {0};
    int r = (h_proto == ETH_P_IP)
                ? build_ipv4_key(l3, data_end, &key, 1)
                : build_ipv6_key(l3, data_end, &key, 1);

    if (r < 0)
    {
        XDP_LOG("couldn't build a rate_key, unsupported protocol=%d", key.protocol);
        return XDP_PASS;
    }
    if (r == 0)
    {
        XDP_LOG("parse failure protocol=%d", key.protocol);
        return XDP_PASS;
    }
    if (r == 2)
    {
        XDP_LOG("IPv6 fragment packet");
        return XDP_PASS;
    }

    struct flow_policy *pol = bpf_map_lookup_elem(&flow_map, &key);
    if (!pol)
    {
        XDP_LOG("blocklist miss proto=%d src_port=%d dst_port=%d",
                key.protocol, key.src_port, key.dst_port);
        return XDP_DROP;
    }

    if (pol->action == BLOCK)
    {
        XDP_LOG("block action");
        return XDP_DROP;
    }

    struct rate_bucket *bucket = bpf_map_lookup_elem(&ingress_buckets, &key);
    if (!bucket)
    {
        XDP_LOG("no ingress bucket");
        return XDP_DROP;
    }

    if (bucket_allow(bucket, size))
    {
        XDP_LOG("bucket pass size=%u", size);
        return XDP_PASS;
    }

    if (pol->strategy == STRATEGY_DROP)
    {
        XDP_LOG("ingress strategy DROP");
        return XDP_DROP;
    }

    if (pol->strategy == STRATEGY_ECN)
    {
        int marked = key.family == FLOW_FAMILY_IPV4
                         ? ipv4_mark_ecn((struct iphdr *)l3)
                         : ipv6_mark_ecn((struct ipv6hdr *)l3);
        if (!marked)
        {
            XDP_LOG("ECN not supported family=%d", key.family);
            return XDP_DROP;
        }
    }

    XDP_LOG("pass");
    return XDP_PASS;
}
