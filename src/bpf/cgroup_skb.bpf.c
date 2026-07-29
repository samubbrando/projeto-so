#include "vmlinux.h"
#include "common/monitor.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct proc_key {
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct proc_key);
    __type(value, struct flow_info);
} proc_rule_map SEC(".maps");

SEC("cgroup/connect4")
int cg_connect4(struct bpf_sock_addr *ctx)
{
    struct proc_key pk = {0};
    bpf_get_current_comm(&pk.comm, sizeof(pk.comm));

    struct flow_info *info = bpf_map_lookup_elem(&proc_rule_map, &pk);
    if (info) {
        if (info->action == BLOCK) return 0;
        return 1;
    }

    struct proc_key wc = { .comm = "*" };
    info = bpf_map_lookup_elem(&proc_rule_map, &wc);
    if (info) {
        if (info->action == BLOCK) return 0;
    }

    return 1;
}

SEC("cgroup/sendmsg4")
int cg_sendmsg4(struct bpf_sock_addr *ctx)
{
    struct proc_key pk = {0};
    bpf_get_current_comm(&pk.comm, sizeof(pk.comm));

    struct flow_info *info = bpf_map_lookup_elem(&proc_rule_map, &pk);
    if (info) {
        if (info->action == BLOCK) return 0;
        return 1;
    }

    struct proc_key wc = { .comm = "*" };
    info = bpf_map_lookup_elem(&proc_rule_map, &wc);
    if (info) {
        if (info->action == BLOCK) return 0;
    }

    return 1;
}

SEC("cgroup/connect6")
int cg_connect6(struct bpf_sock_addr *ctx)
{
    struct proc_key pk = {0};
    bpf_get_current_comm(&pk.comm, sizeof(pk.comm));

    struct flow_info *info = bpf_map_lookup_elem(&proc_rule_map, &pk);
    if (info) {
        if (info->action == BLOCK) return 0;
        return 1;
    }

    struct proc_key wc = { .comm = "*" };
    info = bpf_map_lookup_elem(&proc_rule_map, &wc);
    if (info) {
        if (info->action == BLOCK) return 0;
    }

    return 1;
}

SEC("cgroup/sendmsg6")
int cg_sendmsg6(struct bpf_sock_addr *ctx)
{
    struct proc_key pk = {0};
    bpf_get_current_comm(&pk.comm, sizeof(pk.comm));

    struct flow_info *info = bpf_map_lookup_elem(&proc_rule_map, &pk);
    if (info) {
        if (info->action == BLOCK) return 0;
        return 1;
    }

    struct proc_key wc = { .comm = "*" };
    info = bpf_map_lookup_elem(&proc_rule_map, &wc);
    if (info) {
        if (info->action == BLOCK) return 0;
    }

    return 1;
}

