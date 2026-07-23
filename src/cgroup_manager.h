#ifndef CGROUP_MANAGER_H
#define CGROUP_MANAGER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <bpf/libbpf.h>
#include "common/config.h"
#include "common/monitor.h"
#include "net-funcs.h"
#include "bpf/cgroup_skb.skel.h"

#define CGROUP_ROOT "/sys/fs/cgroup"

static __u64 get_pid_cgroup_id(pid_t pid)
{
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/cgroup", pid);

    FILE *f = fopen(proc_path, "r");
    if (!f) return 0;

    char line[512];
    if (!fgets(line, sizeof(line), f)) { fclose(f); return 0; }
    fclose(f);

    char *p = strchr(line, ':');
    if (!p) return 0;
    p = strchr(p + 1, ':');
    if (!p) return 0;
    p++;

    char *nl = strchr(p, '\n');
    if (nl) *nl = '\0';

    char cg_path[1024];
    snprintf(cg_path, sizeof(cg_path), "%s%s", CGROUP_ROOT, p);

    struct stat st;
    if (stat(cg_path, &st)) return 0;
    return (__u64)st.st_ino;
}

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
    int cg_fd = open(CGROUP_ROOT, O_DIRECTORY | O_RDONLY);
    if (cg_fd < 0)
    {
        fprintf(stderr, "Cannot open %s\n", CGROUP_ROOT);
        return -1;
    }

    struct bpf_link *egress_link = bpf_program__attach_cgroup(
        skel->progs.cg_egress, cg_fd);
    if (!egress_link)
    {
        fprintf(stderr, "Failed to attach cgroup_skb/egress\n");
        close(cg_fd);
        return -1;
    }
    skel->links.cg_egress = egress_link;

    struct bpf_link *ingress_link = bpf_program__attach_cgroup(
        skel->progs.cg_ingress, cg_fd);
    if (!ingress_link)
    {
        fprintf(stderr, "Failed to attach cgroup_skb/ingress\n");
        close(cg_fd);
        return -1;
    }
    skel->links.cg_ingress = ingress_link;

    close(cg_fd);
    printf("cgroup_skb attached to %s (root)!\n", CGROUP_ROOT);
    return 0;
}

static void setup_cgroup_rules(struct cgroup_skb_bpf *skel,
                                socket_proccess_t *sockets, int n_sockets,
                                const struct rule *rules, int n_rules,
                                unsigned long long capacity_bps)
{
    for (int i = 0; i < n_sockets; i++)
    {
        if (sockets[i].pid[0] == '\0') continue;
        if (sockets[i].name[0] == '\0') continue;

        int pid = atoi(sockets[i].pid);
        if (pid <= 0) continue;

        const struct rule *rule = match_rule(rules, n_rules, sockets[i].name);
        if (!rule) continue;

        __u64 cgid = get_pid_cgroup_id(pid);
        if (!cgid) continue;

        unsigned int rate_bps = (unsigned int)(capacity_bps * rule->bandwidth_pct / 100);
        struct flow_info fi = {
            .action = rule->action,
            .egress_strategy = rule->egress_strategy,
            .ingress_strategy = rule->ingress_strategy,
            .rate_bps = rate_bps,
        };

        if (bpf_map__update_elem(skel->maps.cgroup_rule_map,
                                 &cgid, sizeof(cgid), &fi, sizeof(fi), BPF_ANY))
            fprintf(stderr, "cgroup_rule_map update failed for PID %d (%s)\n",
                    pid, sockets[i].name);

        if (rate_bps > 0)
        {
            unsigned int burst = rate_bps / 8;
            struct rate_bucket rb = {
                .tokens = burst,
                .last_ns = 0,
                .rate_bps = rate_bps,
                .burst = burst,
            };
            if (bpf_map__update_elem(skel->maps.cg_egress_buckets,
                                     &cgid, sizeof(cgid), &rb, sizeof(rb), BPF_ANY))
                fprintf(stderr, "cg_egress_buckets update failed for PID %d\n", pid);
            if (bpf_map__update_elem(skel->maps.cg_ingress_buckets,
                                     &cgid, sizeof(cgid), &rb, sizeof(rb), BPF_ANY))
                fprintf(stderr, "cg_ingress_buckets update failed for PID %d\n", pid);
        }
    }
}

static void cleanup_cgroup_skb_bpf(struct cgroup_skb_bpf *skel)
{
    cgroup_skb_bpf__destroy(skel);
}

#endif