#include "vmlinux.h"
#include "hist.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_ENTRIES 4096

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct conn_key);
    __type(value, struct hist); 
} hists SEC(".maps");

static struct hist zero;

SEC("fentry/tcp_rcv_established")
int BPF_PROG(
    tcp_rcv, // Nome do programa 
    struct sock *sk
) {
    struct conn_key key = {};
    struct hist *histp; // Eu recebo um ponteiro do ebpf
    struct tcp_sock *tp = (struct tcp_sock *) sk;

    u16 src_port  =  BPF_CORE_READ(sk, __sk_common.skc_num);
    u32 src_ip = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    
    u16 dst_port  = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    u32 dst_ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);

    u32 rtt = BPF_CORE_READ(tp, srtt_us) >> 3; // Linux armazena escalado p 8

    u64 sent = BPF_CORE_READ(tp, bytes_acked);
    u64 received = BPF_CORE_READ(tp, bytes_received);
    
    key.src_port = src_port;
    key.src_ip = src_ip;
    key.dst_port = dst_port;
    key.dst_ip = dst_ip;

    histp = bpf_map_lookup_elem(&hists, &key);

    if (!histp) {
        bpf_map_update_elem(&hists, &key, &zero, BPF_ANY);

        histp = bpf_map_lookup_elem(&hists, &key);
        if (!histp)
            return 0;
    }

    histp->rtt = rtt;
    histp->sent = sent;
    histp->received = received;

    return 0;
}
