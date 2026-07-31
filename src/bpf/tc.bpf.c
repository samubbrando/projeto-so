#include "vmlinux.h"
#include "common/monitor.h"
#include "bpf_common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TC_ACT_OK 0
#define TC_ACT_SHOT 1
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_HOPOPTS 0
#define IPPROTO_ROUTING 43
#define IPPROTO_FRAGMENT 44
#define IPPROTO_DSTOPTS 60
#define IPPROTO_ESP 50
#define IPPROTO_AH 51

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct egress_stats);
} egress_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct flow_key);
    __type(value, struct flow_info);
} flow_info_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct flow_key);
    __type(value, struct rate_bucket);
} egress_buckets SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct flow_key_v6);
    __type(value, struct flow_info);
} flow_info_map_v6 SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct flow_key_v6);
    __type(value, struct rate_bucket);
} egress_buckets_v6 SEC(".maps");


SEC("tc/egress")
int tc_egress(struct __sk_buff *skb)
{
    __u32 zero = 0;
    struct egress_stats *stats = bpf_map_lookup_elem(&egress_map, &zero);
    if (!stats)
        return TC_ACT_OK;

    __sync_fetch_and_add(&stats->bytes, skb->len);
    __sync_fetch_and_add(&stats->packets, 1);

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *ethdr = data;
    if ((void *)(ethdr + 1) > data_end)
        return TC_ACT_OK;

    unsigned short h_proto = bpf_ntohs(ethdr->h_proto);
    if (h_proto == ETH_P_IP)
    {
        struct iphdr *iph = data + sizeof(struct ethhdr);
        if ((void *)(iph + 1) > data_end) return TC_ACT_OK;

        struct flow_key key = {
            .src_ip = iph->saddr,
            .dst_ip = iph->daddr,
            .protocol = iph->protocol
        };

        void *l4 = data + sizeof(struct ethhdr) + (iph->ihl * 4);
        if (iph->protocol == IPPROTO_TCP) {
            if (!parse_transport(l4, data_end, &key, NULL, 0)) return TC_ACT_OK;
        } else if (iph->protocol == IPPROTO_UDP) {
            if (!parse_udp(l4, data_end, &key, NULL, 0)) return TC_ACT_OK;
        } else {
            return TC_ACT_OK;
        }

        struct flow_info *info = bpf_map_lookup_elem(&flow_info_map, &key);
        if (!info) {
            bpf_printk("TC: flow NOT FOUND proto=%d src_port=%d dst_port=%d",
                       key.protocol, key.src_port, key.dst_port);
            return TC_ACT_SHOT;
        }

        if (info->action == BLOCK)
            return TC_ACT_SHOT;

        struct rate_bucket *bucket = bpf_map_lookup_elem(&egress_buckets, &key);
        if (!bucket)
            return TC_ACT_OK;

        refill_bucket(bucket);
        if (bucket->tokens >= skb->len)
        {
            __sync_fetch_and_sub(&bucket->tokens, skb->len);
            return TC_ACT_OK;
        }

        if (info->egress_strategy == STRATEGY_DROP)
            return TC_ACT_SHOT;

        return TC_ACT_OK;
    }

    if (h_proto == ETH_P_IPV6)
    {
        struct ipv6hdr *ip6h = data + sizeof(struct ethhdr);
        if ((void *)(ip6h + 1) > data_end)
            return TC_ACT_OK;

        struct flow_key_v6 key_v6 = {0};
        __builtin_memcpy(key_v6.src_ip, ip6h->saddr.in6_u.u6_addr8, 16);
        __builtin_memcpy(key_v6.dst_ip, ip6h->daddr.in6_u.u6_addr8, 16);
        key_v6.protocol = ip6h->nexthdr;

        unsigned char nexthdr = ip6h->nexthdr;
        void *l6 = data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);

#pragma unroll
        for (int i = 0; i < 4; i++)
        {
            if (nexthdr == IPPROTO_TCP) {
                if (!parse_transport(l6, data_end, NULL, &key_v6, 1)) return TC_ACT_OK;
                break;
            }
            if (nexthdr == IPPROTO_UDP) {
                if (!parse_udp(l6, data_end, NULL, &key_v6, 1)) return TC_ACT_OK;
                break;
            }
            if (nexthdr == IPPROTO_HOPOPTS || nexthdr == IPPROTO_ROUTING ||
                nexthdr == IPPROTO_DSTOPTS || nexthdr == IPPROTO_FRAGMENT ||
                nexthdr == IPPROTO_AH) {
                struct ipv6_opt_hdr *opthdr = l6;
                if ((void *)(opthdr + 1) > data_end) return TC_ACT_OK;
                nexthdr = opthdr->nexthdr;

                if (nexthdr == IPPROTO_FRAGMENT) {
                    struct frag_hdr *fraghdr = l6;
                    if ((void *)(fraghdr + 1) > data_end) return TC_ACT_OK;
                    l6 = (void *)(fraghdr + 1);
                    key_v6.protocol = fraghdr->nexthdr;
                    return TC_ACT_OK;
                }
                unsigned int hdrlen = (opthdr->hdrlen + 1) * 8;
                l6 += hdrlen;
                continue;
            }
            return TC_ACT_OK;
        }

        if (key_v6.protocol != IPPROTO_TCP && key_v6.protocol != IPPROTO_UDP)
            return TC_ACT_OK;

        struct flow_info *info = bpf_map_lookup_elem(&flow_info_map_v6, &key_v6);
        if (!info) {
            bpf_printk("TC: flow_v6 NOT FOUND proto=%d src_port=%d dst_port=%d",
                       key_v6.protocol, key_v6.src_port, key_v6.dst_port);
            return TC_ACT_SHOT;
        }

        if (info->action == BLOCK)
            return TC_ACT_SHOT;

        struct rate_bucket *bucket = bpf_map_lookup_elem(&egress_buckets_v6, &key_v6);
        if (!bucket)
            return TC_ACT_OK;

        refill_bucket(bucket);
        if (bucket->tokens >= skb->len)
        {
            __sync_fetch_and_sub(&bucket->tokens, skb->len);
            return TC_ACT_OK;
        }

        if (info->egress_strategy == STRATEGY_DROP)
            return TC_ACT_SHOT;

        return TC_ACT_OK;
    }

    return TC_ACT_OK;
}
