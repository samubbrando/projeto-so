#ifndef CGROUP_MANAGER_H
#define CGROUP_MANAGER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bpf/libbpf.h>
#include "common/config.h"
#include "common/monitor.h"
#include "net-funcs.h"
#include "bpf/cgroup_skb.skel.h"

static struct cgroup_skb_bpf *init_cgroup_skb_bpf(void)
{
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    struct cgroup_skb_bpf *skel = cgroup_skb_bpf__open_and_load();
    if (!skel)
    {
        fprintf(stderr, "Failed to load cgroup_skb BPF\n");
        return NULL;
    }
    printf("BPF loaded (cgroup_skb)!\n");
    return skel;
}

static int attach_cgroup_skb_bpf(struct cgroup_skb_bpf *skel) {
    if (cgroup_skb_bpf__attach(skel)) 
    {
        fprintf(stderr, "Failure attaching BPF (CGROUP_SKB)\n");
        return 1;
    }

    printf("BPF program attached (CGROUP_SKB)!\n");
    return 0;
}

static void setup_cgroup_rules(struct cgroup_skb_bpf *skel,
                                socket_proccess_t *sockets, int n_sockets,
                                const struct rule *rules, int n_rules)
{
    struct proc_key {
        char comm[16];
    };

    struct proc_key zero_key = {0};
    struct proc_key next_key = {0};
    while (bpf_map__get_next_key(skel->maps.proc_rule_map, &zero_key, &next_key, sizeof(struct proc_key)) == 0)
    {
        bpf_map__delete_elem(skel->maps.proc_rule_map, &next_key, sizeof(struct proc_key), 0);
        memcpy(&zero_key, &next_key, sizeof(struct proc_key));
    }

    for (int i = 0; i < n_sockets; i++)
    {
        if (sockets[i].pid[0] == '\0') continue;
        if (sockets[i].name[0] == '\0') continue;

        const struct rule *rule = match_rule(rules, n_rules, sockets[i].name);
        if (!rule) continue;

        struct flow_info fi = {
            .action = rule->action,
            .egress_strategy = rule->egress_strategy,
            .ingress_strategy = rule->ingress_strategy,
        };

        struct proc_key pk = {0};
        strncpy(pk.comm, sockets[i].name, sizeof(pk.comm) - 1);
        if (bpf_map__update_elem(skel->maps.proc_rule_map,
                                 &pk, sizeof(pk), &fi, sizeof(fi), BPF_ANY))
            fprintf(stderr, "proc_rule_map update failed for %s\n", sockets[i].name);
    }

    for (int i = 0; i < n_rules; i++)
    {
        if (strcmp(rules[i].comm, "*") == 0)
        {
            struct flow_info fi = {
                .action = rules[i].action,
                .egress_strategy = rules[i].egress_strategy,
                .ingress_strategy = rules[i].ingress_strategy,
            };
            struct proc_key pk = { .comm = "*" };
            bpf_map__update_elem(skel->maps.proc_rule_map,
                                 &pk, sizeof(pk), &fi, sizeof(fi), BPF_ANY);
            break;
        }
    }
}

static void cleanup_cgroup_skb_bpf(struct cgroup_skb_bpf *skel)
{
    cgroup_skb_bpf__destroy(skel);
}

#endif