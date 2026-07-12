#include "vmlinux.h"
#include "common/monitor.h"
#include <bpf/bpf_helpers.h>

char LICENCE[] SEC("license") = "Dual BSD/GPL";

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ingress_stats);
} ingress_map SEC(".maps");

/*
struct xdp_md {
    __u32 data;           // Pointer to the start of the packet payload
    __u32 data_end;       // Pointer to the end of the packet payload
    __u32 data_meta;      // Pointer to optional XDP metadata area
    __u32 ingress_ifindex;// Index of the network interface receiving the packet
    __u32 rx_queue_index; // Index of the RX queue where the packet was received
    __u32 egress_ifindex; // Index of the network interface for egress redirection
};
*/

SEC("xdp")
int xdp_ingress(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 size = data_end - data;

    __u32 key = 0;
    struct ingress_stats *stats = bpf_map_lookup_elem(&ingress_map, &key);

    if (!stats)
        return XDP_PASS;

    __sync_fetch_and_add(&stats->packets, 1);
    __sync_fetch_and_add(&stats->bytes, size);

    return XDP_PASS;
}