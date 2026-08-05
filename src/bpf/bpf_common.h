#ifndef BPF_COMMON_H
#define BPF_COMMON_H

#include "vmlinux.h"
#include "common/monitor.h"
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
#define IPPROTO_AH 51

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

static __always_inline int bucket_allow(struct rate_bucket *bucket, __u64 size)
{
    refill_bucket(bucket);
    if (bucket->tokens < size)
        return 0;
    __sync_fetch_and_sub(&bucket->tokens, size);
    return 1;
}

static __always_inline int parse_l4_ports(void *data, void *data_end,
                                          struct flow_key *key)
{
    struct tcphdr *h = data;
    if ((void *)(h + 1) > data_end)
        return 0;
    key->src_port = bpf_ntohs(h->source);
    key->dst_port = bpf_ntohs(h->dest);
    return 1;
}

/*
 * Build a unified flow key from an IPv4 header. Returns:
 *   1  key filled (TCP/UDP with ports)
 *   0  header too small or L4 truncated
 *  -1  unsupported L4 protocol
 * With is_ingress, addresses and ports are swapped so the key matches the
 * local->remote orientation stored by the orchestrator.
 */
static __always_inline int build_ipv4_key(struct iphdr *iph, void *data_end,
                                          struct flow_key *key, int is_ingress)
{
    if ((void *)(iph + 1) > data_end)
        return 0;

    key->family = FLOW_FAMILY_IPV4;
    key->protocol = iph->protocol;
    if (is_ingress)
    {
        key->addr.ip4[0] = iph->daddr;
        key->addr.ip4[1] = iph->saddr;
    }
    else
    {
        key->addr.ip4[0] = iph->saddr;
        key->addr.ip4[1] = iph->daddr;
    }

    if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
        return -1;

    void *l4 = (void *)iph + iph->ihl * 4;
    if (!parse_l4_ports(l4, data_end, key))
        return 0;

    if (is_ingress)
    {
        __u16 tmp = key->src_port;
        key->src_port = key->dst_port;
        key->dst_port = tmp;
    }
    return 1;
}

/*
 * Build a unified flow key from an IPv6 header, walking extension headers.
 * Returns:
 *   1  key filled (TCP/UDP with ports)
 *   2  fragment header seen; no ports, caller should pass unkeyed
 *   0  header too small or L4 truncated
 *  -1  unsupported next header
 */
static __always_inline int build_ipv6_key(struct ipv6hdr *ip6h, void *data_end,
                                          struct flow_key *key, int is_ingress)
{
    if ((void *)(ip6h + 1) > data_end)
        return 0;

    key->family = FLOW_FAMILY_IPV6;
    if (is_ingress)
    {
        __builtin_memcpy(key->addr.ip6, ip6h->daddr.in6_u.u6_addr8, 16);
        __builtin_memcpy(key->addr.ip6 + 16, ip6h->saddr.in6_u.u6_addr8, 16);
    }
    else
    {
        __builtin_memcpy(key->addr.ip6, ip6h->saddr.in6_u.u6_addr8, 16);
        __builtin_memcpy(key->addr.ip6 + 16, ip6h->daddr.in6_u.u6_addr8, 16);
    }

    unsigned char nexthdr = ip6h->nexthdr;
    key->protocol = nexthdr;
    void *l6 = (void *)ip6h + sizeof(struct ipv6hdr);

#pragma unroll
    for (int i = 0; i < 4; i++)
    {
        if (nexthdr == IPPROTO_TCP || nexthdr == IPPROTO_UDP)
        {
            if (!parse_l4_ports(l6, data_end, key))
                return 0;
            if (is_ingress)
            {
                __u16 tmp = key->src_port;
                key->src_port = key->dst_port;
                key->dst_port = tmp;
            }
            return 1;
        }

        if (nexthdr == IPPROTO_HOPOPTS || nexthdr == IPPROTO_ROUTING ||
            nexthdr == IPPROTO_DSTOPTS || nexthdr == IPPROTO_FRAGMENT ||
            nexthdr == IPPROTO_AH)
        {
            struct ipv6_opt_hdr *opthdr = l6;
            if ((void *)(opthdr + 1) > data_end)
                return 0;

            if (nexthdr == IPPROTO_FRAGMENT)
                return 2;

            nexthdr = opthdr->nexthdr;
            key->protocol = nexthdr;
            l6 += (opthdr->hdrlen + 1) * 8;
            continue;
        }

        return -1;
    }

    return -1;
}

static __always_inline __u16 csum_fold16(__u32 csum)
{
    csum = (csum & 0xFFFF) + (csum >> 16);
    csum = (csum & 0xFFFF) + (csum >> 16);
    return (__u16)csum;
}

/*
 * Set ECN CE on an IPv4 packet. Returns 1 if CE was set, 0 if the packet is
 * not ECN-capable (Not-ECT) or already marked (CE). The header checksum is
 * updated incrementally: tos is the low byte of header word 0, so
 * check' = check + (old_tos - new_tos) mod (2^16 - 1).
 */
static __always_inline int ipv4_mark_ecn(struct iphdr *iph)
{
    __u8 old_tos = iph->tos;
    __u8 ecn = old_tos & 0x03;
    if (!ecn || ecn == 3)
        return 0;

    __u8 new_tos = (old_tos & 0xFC) | 0x03;
    __s32 delta = (__s32)old_tos - (__s32)new_tos;
    if (delta < 0)
        delta += 0xFFFF;

    __u16 check = csum_fold16((__u32)bpf_ntohs(iph->check) + (__u32)delta);
    if (check == 0)
        check = 0xFFFF;

    iph->check = bpf_htons(check);
    iph->tos = new_tos;
    return 1;
}

/*
 * Set ECN CE on an IPv6 packet. The ECN bits are the two low bits of the
 * traffic class, which live in bits 4-5 of flow_lbl[0] (mask 0x30).
 * Returns 1 if CE was set, 0 if the packet is not ECN-capable or already CE.
 */
static __always_inline int ipv6_mark_ecn(struct ipv6hdr *ip6h)
{
    __u8 ecn = (ip6h->flow_lbl[0] & 0x30) >> 4;
    if (!ecn || ecn == 3)
        return 0;
    ip6h->flow_lbl[0] = (ip6h->flow_lbl[0] & ~0x30) | 0x30;
    return 1;
}

#endif
