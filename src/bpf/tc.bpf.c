#include "vmlinux.h"
#include "common/monitor.h"
#include "bpf_common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


// I needed to define the constants because the following include
// used to cause errors.
// #include <linux/pkt_cls.h>

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

#define TC_LOG(fmt, ...) bpf_printk("TC: " fmt, ##__VA_ARGS__)

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct traffic_stats);
} egress_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct flow_key);
    __type(value, struct flow_policy);
} flow_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct flow_key);
    __type(value, struct rate_bucket);
} egress_buckets SEC(".maps");

SEC("tc/egress")
int tc_egress(struct __sk_buff *skb)
{
    __u32 stats_key = 0;
    struct traffic_stats *stats = bpf_map_lookup_elem(&egress_map, &stats_key);
    if (!stats)
    {
        TC_LOG("missing egress stats");
        return TC_ACT_OK;
    }

    __sync_fetch_and_add(&stats->bytes, skb->len);
    __sync_fetch_and_add(&stats->packets, 1);

    if (skb->mark == PROBE_FWMARK)
    {
        TC_LOG("probe mark");
        return TC_ACT_OK;
    }

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    unsigned short h_proto = bpf_ntohs(eth->h_proto);
    if (h_proto != ETH_P_IP && h_proto != ETH_P_IPV6)
    {
        TC_LOG("unsupported ether h_proto=%u, scheduler only supports %u %u", h_proto, ETH_P_IP, ETH_P_IPV6);
        return TC_ACT_OK;
    }

    struct flow_key key = {0};
    void *l3 = data + sizeof(struct ethhdr);
    int r = (h_proto == ETH_P_IP)
            ? build_ipv4_key(l3, data_end, &key, 0)
            : build_ipv6_key(l3, data_end, &key, 0);

    if (r < 0)
    {
        TC_LOG("couldn't build a rate_key, unsupported protocol=%d", key.protocol);
        return TC_ACT_OK;
    }
    if (r == 0)
    {
        TC_LOG("parse failure protocol=%d", key.protocol);
        return TC_ACT_OK;
    }
    if (r == 2)
    {
        TC_LOG("IPv6 fragment packet");
        return TC_ACT_OK;
    }

    struct flow_policy *pol = bpf_map_lookup_elem(&flow_map, &key);
    if (!pol)
    {
        TC_LOG("flow NOT FOUND h_proto=%d src_port=%d dst_port=%d",
               key.protocol, key.src_port, key.dst_port);
        return TC_ACT_SHOT;
    }

    if (pol->action == BLOCK)
    {
        TC_LOG("flow BLOCK action");
        return TC_ACT_SHOT;
    }

    struct rate_bucket *bucket = bpf_map_lookup_elem(&egress_buckets, &key);
    if (!bucket)
    {
        TC_LOG("no egress bucket");
        return TC_ACT_SHOT;
    }

    if (bucket_allow(bucket, skb->len))
    {
        TC_LOG("token bucket pass size=%u", skb->len);
        return TC_ACT_OK;
    }

    if (pol->strategy == STRATEGY_DROP)
    {
        TC_LOG("egress strategy DROP");
        return TC_ACT_SHOT;
    }

    TC_LOG("egress pass");
    return TC_ACT_OK;
}
