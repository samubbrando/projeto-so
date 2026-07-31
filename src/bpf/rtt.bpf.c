#include "vmlinux.h"
#include "common/hist.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";


#define AF_INET 2
#define AF_INET6 10
#define MAX_ENTRIES 4096

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct conn_key);
    __type(value, struct hist);
} tcp_hists SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct conn_key);
    __type(value, struct hist);
} udp_hists SEC(".maps");

static struct hist zero;

SEC("fentry/tcp_rcv_established")
int BPF_PROG(tcp_rcv, struct sock *sk)
{
    struct conn_key key = {};
    struct tcp_sock *tp = (struct tcp_sock *)sk;

    key.src_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    key.dst_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    key.protocol = 6;

    if (BPF_CORE_READ(sk, __sk_common.skc_family) == AF_INET6) {
        key.family = AF_INET6;
        BPF_CORE_READ_INTO(&key.src_ip, sk, __sk_common.skc_v6_rcv_saddr);
        BPF_CORE_READ_INTO(&key.dst_ip, sk, __sk_common.skc_v6_daddr);
    } else {
        key.family = AF_INET;
        __u32 src = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        __u32 dst = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        __builtin_memcpy(key.src_ip, &src, 4);
        __builtin_memcpy(key.dst_ip, &dst, 4);
    }

    u32 rtt = BPF_CORE_READ(tp, srtt_us) >> 3;
    u64 sent = BPF_CORE_READ(tp, bytes_acked);
    u64 received = BPF_CORE_READ(tp, bytes_received);
    
    struct hist *histp = bpf_map_lookup_elem(&tcp_hists, &key);
    if (!histp) {
        bpf_map_update_elem(&tcp_hists, &key, &zero, BPF_ANY);
        histp = bpf_map_lookup_elem(&tcp_hists, &key);
        if (!histp) return 0;
    }
    
    histp->rtt = rtt;
    histp->tx_bytes = sent;
    histp->rx_bytes = received;
    return 0;
}

SEC("fentry/udp_recvmsg")
int BPF_PROG(udp_recv, struct sock *sk, struct msghdr *msg, size_t len, int flags, int *addr_len)
{
    struct conn_key key = {};
    
    key.src_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    key.dst_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    key.protocol = 17;

    if (BPF_CORE_READ(sk, __sk_common.skc_family) == AF_INET6) {
        key.family = AF_INET6;
        BPF_CORE_READ_INTO(&key.src_ip, sk, __sk_common.skc_v6_rcv_saddr);
        BPF_CORE_READ_INTO(&key.dst_ip, sk, __sk_common.skc_v6_daddr);
    } else {
        key.family = AF_INET;
        __u32 src = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        __u32 dst = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        __builtin_memcpy(key.src_ip, &src, 4);
        __builtin_memcpy(key.dst_ip, &dst, 4);
    }

    struct hist *histp = bpf_map_lookup_elem(&udp_hists, &key);
    unsigned long long curr_time = bpf_ktime_get_ns() / 1000;
    if (!histp) {
        bpf_map_update_elem(&udp_hists, &key, &zero, BPF_ANY);
        histp = bpf_map_lookup_elem(&udp_hists, &key);
        if (!histp) return 0;
    }

    __sync_fetch_and_add(&histp->rx_bytes, len);

    if (histp->prev_msr != 0) 
        histp->rtt = curr_time - histp->prev_msr;
    histp->prev_msr = curr_time;
    
    return 0;
}

SEC("fentry/udp_sendmsg")
int BPF_PROG(udp_send, struct sock *sk, struct msghdr *msg, size_t len)
{
    struct conn_key key = {};

    key.src_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    key.dst_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    key.protocol = 17;

    if (BPF_CORE_READ(sk, __sk_common.skc_family) == AF_INET6) {
        key.family = AF_INET6;
        BPF_CORE_READ_INTO(&key.src_ip, sk, __sk_common.skc_v6_rcv_saddr);
        BPF_CORE_READ_INTO(&key.dst_ip, sk, __sk_common.skc_v6_daddr);
    } else {
        key.family = AF_INET;
        __u32 src = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        __u32 dst = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        __builtin_memcpy(key.src_ip, &src, 4);
        __builtin_memcpy(key.dst_ip, &dst, 4);
    }

    struct hist *histp = bpf_map_lookup_elem(&udp_hists, &key);
    unsigned long long curr_time = bpf_ktime_get_ns() / 1000;

    if (!histp) {
        bpf_map_update_elem(&udp_hists, &key, &zero, BPF_ANY);
        histp = bpf_map_lookup_elem(&udp_hists, &key);
        if (!histp) return 0;
    }
    __sync_fetch_and_add(&histp->tx_bytes, len);

    if (histp->prev_msr != 0) 
        histp->rtt = curr_time - histp->prev_msr;
    histp->prev_msr = curr_time;

    return 0;
}
