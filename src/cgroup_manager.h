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

#define CGROUP_ROOT "/sys/fs/cgroup/so"
#define MAX_CGROUPS 64

struct cgroup_entry {
    char name[16];
    __u64 cgid;
    int cgid_set;
};

static struct cgroup_entry cg_entries[MAX_CGROUPS];
static int n_cg_entries = 0;
static char cgroup_root[256];

static int init_cgroup_fs(void)
{
    snprintf(cgroup_root, sizeof(cgroup_root), "%s", CGROUP_ROOT);

    struct stat st;
    if (stat(cgroup_root, &st) == 0)
    {
        system("rmdir /sys/fs/cgroup/so/* 2>/dev/null");
    }
    else
    {
        if (mkdir(cgroup_root, 0755) && stat(cgroup_root, &st))
        {
            fprintf(stderr, "Failed to create %s (needs cgroupv2)\n", cgroup_root);
            return -1;
        }
    }
    return 0;
}

static int create_rule_cgroup(const char *name)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", cgroup_root, name);
    if (mkdir(path, 0755) && errno != EEXIST)
    {
        fprintf(stderr, "Failed to create cgroup %s\n", path);
        return -1;
    }
    return 0;
}

static __u64 get_cgroup_id(const char *name)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", cgroup_root, name);
    struct stat st;
    if (stat(path, &st))
    {
        fprintf(stderr, "Cannot stat cgroup %s\n", path);
        return 0;
    }
    return (__u64)st.st_ino;
}

static int move_pid_to_cgroup(pid_t pid, const char *name)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/%s/cgroup.procs", cgroup_root, name);
    FILE *f = fopen(path, "w");
    if (!f) {
        fprintf(stderr, "Cannot open %s\n", path);
        return -1;
    }
    fprintf(f, "%d", pid);
    fclose(f);
    return 0;
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
    int cg_fd = open(cgroup_root, O_DIRECTORY | O_RDONLY);
    if (cg_fd < 0)
    {
        fprintf(stderr, "Cannot open %s\n", cgroup_root);
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
    printf("cgroup_skb attached to %s!\n", cgroup_root);
    return 0;
}

static void setup_cgroup_rules(struct cgroup_skb_bpf *skel,
                                const struct rule *rules, int n_rules,
                                unsigned long long capacity_bps)
{
    n_cg_entries = 0;

    for (int i = 0; i < n_rules; i++)
    {
        if (strcmp(rules[i].comm, "*") == 0)
        {
            strncpy(cg_entries[0].name, "default", sizeof(cg_entries[0].name) - 1);
            continue;
        }

        char safe_name[16];
        strncpy(safe_name, rules[i].comm, sizeof(safe_name) - 1);
        for (char *p = safe_name; *p; p++)
            if (*p == '/' || *p == '.') *p = '_';

        if (n_cg_entries < MAX_CGROUPS)
        {
            strncpy(cg_entries[n_cg_entries].name, safe_name,
                    sizeof(cg_entries[n_cg_entries].name) - 1);
            n_cg_entries++;
        }
    }

    for (int i = 0; i <= n_cg_entries; i++)
    {
        const char *name = (i == 0) ? "default" : cg_entries[i].name;
        if (create_rule_cgroup(name)) continue;

        __u64 cgid = get_cgroup_id(name);
        if (!cgid) continue;

        if (i == 0)
            cg_entries[0].cgid = cgid;
        else
            cg_entries[i].cgid = cgid;

        const struct rule *rule = NULL;
        if (i == 0)
        {
            rule = match_rule(rules, n_rules, "*");
        }
        else
        {
            for (int j = 0; j < n_rules; j++)
                if (strcmp(rules[j].comm, cg_entries[i].name) == 0)
                    rule = &rules[j];
        }

        if (!rule) continue;

        unsigned int rate_bps = (unsigned int)(capacity_bps * rule->bandwidth_pct / 100);
        struct flow_info fi = {
            .action = rule->action,
            .egress_strategy = rule->egress_strategy,
            .ingress_strategy = rule->ingress_strategy,
            .rate_bps = rate_bps,
        };

        if (bpf_map__update_elem(skel->maps.cgroup_rule_map,
                                 &cgid, sizeof(cgid), &fi, sizeof(fi), BPF_ANY))
            fprintf(stderr, "cgroup_rule_map update failed for %s\n", name);

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
                fprintf(stderr, "cg_egress_buckets update failed for %s\n", name);
            if (bpf_map__update_elem(skel->maps.cg_ingress_buckets,
                                     &cgid, sizeof(cgid), &rb, sizeof(rb), BPF_ANY))
                fprintf(stderr, "cg_ingress_buckets update failed for %s\n", name);
        }
    }
}

static void enforce_cgroup_pids(struct cgroup_skb_bpf *skel,
                                 socket_proccess_t *sockets, int n_sockets,
                                 const struct rule *rules, int n_rules)
{
    for (int i = 0; i < n_sockets; i++)
    {
        if (sockets[i].pid[0] == '\0') continue;
        if (sockets[i].name[0] == '\0') continue;

        int pid = atoi(sockets[i].pid);
        if (pid <= 0) continue;

        const struct rule *rule = match_rule(rules, n_rules, sockets[i].name);
        if (!rule) continue;

        const char *cg_name = "default";
        if (strcmp(rule->comm, "*") != 0)
            cg_name = rule->comm;

        move_pid_to_cgroup(pid, cg_name);
    }
}

static void cleanup_cgroup_skb_bpf(struct cgroup_skb_bpf *skel)
{
    cgroup_skb_bpf__destroy(skel);
}

#endif