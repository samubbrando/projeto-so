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

#define MAX_TRACKED_COMMS 256

static char prev_comms[MAX_TRACKED_COMMS][16];
static char cur_comms[MAX_TRACKED_COMMS][16];
static int n_prev_comms;
static int n_cur_comms;

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

static int attach_cgroup_skb_bpf(struct cgroup_skb_bpf *skel)
{
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
    struct proc_key
    {
        char comm[16];
    };

    n_cur_comms = 0;

    for (int i = 0; i < n_sockets; i++)
    {
        if (sockets[i].name[0] == '\0')
            continue;

        if (n_cur_comms < MAX_TRACKED_COMMS)
        {
            strncpy(cur_comms[n_cur_comms], sockets[i].name, 15);
            cur_comms[n_cur_comms][15] = '\0';
            n_cur_comms++;
        }

        if (sockets[i].pid[0] == '\0')
            continue;

        const struct rule *rule = match_rule(rules, n_rules, sockets[i].name);
        if (!rule)
            continue;

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
        if (strcmp(rules[i].comm, "*") != 0)
            continue;

        struct flow_info fi = {
            .action = rules[i].action,
            .egress_strategy = rules[i].egress_strategy,
            .ingress_strategy = rules[i].ingress_strategy,
        };
        struct proc_key pk = {.comm = "*"};
        bpf_map__update_elem(skel->maps.proc_rule_map,
                             &pk, sizeof(pk), &fi, sizeof(fi), BPF_ANY);
        break;
    }

    for (int i = 0; i < n_prev_comms; i++)
    {
        if (memcmp(prev_comms[i], "*", 2) == 0)
            continue;

        int found = 0;
        for (int j = 0; j < n_cur_comms; j++)
        {
            if (memcmp(prev_comms[i], cur_comms[j], 16) == 0)
            {
                found = 1;
                break;
            }
        }

        if (!found)
        {
            struct proc_key pk = {0};
            memcpy(pk.comm, prev_comms[i], 16);
            bpf_map__delete_elem(skel->maps.proc_rule_map, &pk, sizeof(pk), 0);
        }
    }

    n_prev_comms = n_cur_comms;
    n_cur_comms = 0;
}


static void cleanup_cgroup_skb_bpf(struct cgroup_skb_bpf *skel)
{
    cgroup_skb_bpf__destroy(skel);
}

#endif