#include "vmlinux.h"
#include "common/monitor.h"
#include "bpf_common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

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

char LICENCE[] SEC("license") = "Dual BSD/GPL";

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ingress_stats);
} ingress_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct flow_key);
    __type(value, struct block_entry);
} blocklist_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct flow_key);
    __type(value, struct rate_bucket);
} ingress_buckets SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct flow_key_v6);
    __type(value, struct block_entry);
} blocklist_map_v6 SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct flow_key_v6);
    __type(value, struct rate_bucket);
} ingress_buckets_v6 SEC(".maps");

SEC("xdp")
int xdp_ingress(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 size = (__u32)(data_end - data);

    __u32 key = 0;
    struct ingress_stats *stats = bpf_map_lookup_elem(&ingress_map, &key);
    if (!stats)
        return XDP_PASS;

    __sync_fetch_and_add(&stats->packets, 1);
    __sync_fetch_and_add(&stats->bytes, size);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    unsigned short h_proto = bpf_ntohs(eth->h_proto);

    if (h_proto == ETH_P_IP)
    {
        struct iphdr *iph = data + sizeof(struct ethhdr);
        if ((void *)(iph + 1) > data_end)
            return XDP_PASS;

        struct flow_key key = {
            .src_ip = iph->daddr,
            .dst_ip = iph->saddr,
            .protocol = iph->protocol,
        };

        void *l4 = data + sizeof(struct ethhdr) + (iph->ihl * 4);
        if (iph->protocol == IPPROTO_TCP) {
            if (!parse_transport(l4, data_end, &key, NULL, 0)) return XDP_PASS;
        } else if (iph->protocol == IPPROTO_UDP) {
            if (!parse_udp(l4, data_end, &key, NULL, 0)) return XDP_PASS;
        } else {
            return XDP_PASS;
        }

        unsigned short tmp = key.src_port;
        key.src_port = key.dst_port;
        key.dst_port = tmp;

        struct block_entry *entry = bpf_map_lookup_elem(&blocklist_map, &key);
        if (!entry)
            return XDP_DROP;

        if (entry->action == BLOCK)
            return XDP_DROP;

        struct rate_bucket *bucket = bpf_map_lookup_elem(&ingress_buckets, &key);
        if (!bucket)
            return XDP_PASS;

        refill_bucket(bucket);
        if (bucket->tokens >= size)
        {
            __sync_fetch_and_sub(&bucket->tokens, size);
            return XDP_PASS;
        }

        if (entry->ingress_strategy == STRATEGY_DROP)
            return XDP_DROP;

        if (entry->ingress_strategy == STRATEGY_ECN)
        {
            __u8 old_tos = iph->tos;
            __u8 ecn = old_tos & 0x03;

            if (!ecn || ecn == 3)
                return XDP_DROP;

            __u8 new_tos = old_tos & 0xFC | 0x03;
            __u32 csum = bpf_csum_diff(
                &old_tos, sizeof(old_tos), &new_tos, sizeof(new_tos),
                (~bpf_ntohs(iph->check)) & 0xFFFF);

            csum = (csum & 0xFFFF) + (csum >> 16);
            csum = (csum & 0xFFFF) + (csum >> 16);

            iph->check = bpf_htons((__u16)csum);
            iph->tos = new_tos;
        }

        return XDP_PASS;
    }

    if (h_proto == ETH_P_IPV6)
    {
        struct ipv6hdr *ip6h = data + sizeof(struct ethhdr);
        if ((void *)(ip6h + 1) > data_end)
            return XDP_PASS;

        struct flow_key_v6 key6 = {0};
        __builtin_memcpy(key6.src_ip, ip6h->daddr.in6_u.u6_addr8, 16);
        __builtin_memcpy(key6.dst_ip, ip6h->saddr.in6_u.u6_addr8, 16);
        key6.protocol = ip6h->nexthdr;

        unsigned char nexthdr = ip6h->nexthdr;
        void *l6 = data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);

#pragma unroll
        for (int i = 0; i < 4; i++)
        {
            if (nexthdr == IPPROTO_TCP) {
                if (!parse_transport(l6, data_end, NULL, &key6, 1)) return XDP_PASS;
                break;
            }
            if (nexthdr == IPPROTO_UDP) {
                if (!parse_udp(l6, data_end, NULL, &key6, 1)) return XDP_PASS;
                break;
            }
            if (nexthdr == IPPROTO_HOPOPTS || nexthdr == IPPROTO_ROUTING ||
                nexthdr == IPPROTO_DSTOPTS || nexthdr == IPPROTO_FRAGMENT ||
                nexthdr == IPPROTO_AH) {
                struct ipv6_opt_hdr *opthdr = l6;
                if ((void *)(opthdr + 1) > data_end) return XDP_PASS;
                nexthdr = opthdr->nexthdr;

                if (nexthdr == IPPROTO_FRAGMENT) {
                    struct frag_hdr *fraghdr = l6;
                    if ((void *)(fraghdr + 1) > data_end) return XDP_PASS;
                    l6 = (void *)(fraghdr + 1);
                    key6.protocol = fraghdr->nexthdr;
                    return XDP_PASS;
                }
                unsigned int hdrlen = (opthdr->hdrlen + 1) * 8;
                l6 += hdrlen;
                continue;
            }
            return XDP_PASS;
        }

        if (key6.protocol != IPPROTO_TCP && key6.protocol != IPPROTO_UDP)
            return XDP_PASS;

        unsigned short tmp = key6.src_port;
        key6.src_port = key6.dst_port;
        key6.dst_port = tmp;

        struct block_entry *entry = bpf_map_lookup_elem(&blocklist_map_v6, &key6);
        if (!entry)
            return XDP_DROP;

        if (entry->action == BLOCK)
            return XDP_DROP;

        struct rate_bucket *bucket = bpf_map_lookup_elem(&ingress_buckets_v6, &key6);
        if (!bucket)
            return XDP_PASS;

        refill_bucket(bucket);
        if (bucket->tokens >= size)
        {
            __sync_fetch_and_sub(&bucket->tokens, size);
            return XDP_PASS;
        }

        if (entry->ingress_strategy == STRATEGY_DROP)
            return XDP_DROP;

        if (entry->ingress_strategy == STRATEGY_ECN)
        {
            __u8 old_tc = ip6h->priority;
            __u8 ecn = old_tc & 0x03;

            if (!ecn || ecn == 3)
                return XDP_DROP;

            ip6h->priority = (old_tc & 0xFC) | 0x03;
        }

        return XDP_PASS;
    }

    return XDP_PASS;
}
