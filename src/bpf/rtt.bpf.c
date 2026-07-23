#include "vmlinux.h"
#include "common/hist.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_ENTRIES 4096

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct conn_key);
    __type(value, struct hist);
} hists SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct conn_key);
    __type(value, struct udp_stat);
} udp_hists SEC(".maps");

static struct hist zero;
static struct udp_stat zero_udp;

SEC("fentry/tcp_rcv_established")
int BPF_PROG(tcp_rcv, struct sock *sk)
{
    struct conn_key key = {};
    struct hist *histp;
    struct tcp_sock *tp = (struct tcp_sock *)sk;

    key.src_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    key.src_ip = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    key.dst_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    key.dst_ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    key.protocol = 6;

    u32 rtt = BPF_CORE_READ(tp, srtt_us) >> 3;
    u64 sent = BPF_CORE_READ(tp, bytes_acked);
    u64 received = BPF_CORE_READ(tp, bytes_received);

    histp = bpf_map_lookup_elem(&hists, &key);
    if (!histp) {
        bpf_map_update_elem(&hists, &key, &zero, BPF_ANY);
        histp = bpf_map_lookup_elem(&hists, &key);
        if (!histp) return 0;
    }

    histp->rtt = rtt;
    histp->sent = sent;
    histp->received = received;
    return 0;
}

SEC("fentry/udp_recvmsg")
int BPF_PROG(udp_recv, struct sock *sk, struct msghdr *msg, size_t len, int flags, int *addr_len)
{
    struct conn_key key = {};

    key.src_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    key.src_ip = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    key.dst_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    key.dst_ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    key.protocol = 17;

    struct udp_stat *stat = bpf_map_lookup_elem(&udp_hists, &key);
    if (!stat) {
        bpf_map_update_elem(&udp_hists, &key, &zero_udp, BPF_ANY);
        stat = bpf_map_lookup_elem(&udp_hists, &key);
        if (!stat) return 0;
    }
    __sync_fetch_and_add(&stat->rx_bytes, len);
    return 0;
}

SEC("fentry/udp_sendmsg")
int BPF_PROG(udp_send, struct sock *sk, struct msghdr *msg, size_t len)
{
    struct conn_key key = {};

    key.src_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    key.src_ip = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    key.dst_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    key.dst_ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    key.protocol = 17;

    struct udp_stat *stat = bpf_map_lookup_elem(&udp_hists, &key);
    if (!stat) {
        bpf_map_update_elem(&udp_hists, &key, &zero_udp, BPF_ANY);
        stat = bpf_map_lookup_elem(&udp_hists, &key);
        if (!stat) return 0;
    }
    __sync_fetch_and_add(&stat->tx_bytes, len);
    return 0;
}
