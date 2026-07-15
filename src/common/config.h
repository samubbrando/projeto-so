#ifndef CONFIG_H
#define CONFIG_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "monitor.h"

#ifndef DEFAULT_EGRESS_STRATEGY
#define DEFAULT_EGRESS_STRATEGY STRATEGY_DROP
#endif

#ifndef DEFAULT_INGRESS_STRATEGY
#define DEFAULT_INGRESS_STRATEGY STRATEGY_DROP
#endif

struct rule {
    char *comm;
    int bandwidth_pct;
    enum action action;
    enum strategy egress_strategy;
    enum strategy ingress_strategy;
};

static char *skip_ws(char *p)
{
    while (*p == ' ' || *p == '\t') p++;
    return p;
}

static char *read_token(char *p, char **out_start, size_t *out_len)
{
    *out_start = p;
    while (*p && *p != ' ' && *p != '\t' && *p != '\n') p++;
    *out_len = p - *out_start;
    return p;
}

static enum action parse_action(char *start, size_t len)
{
    if (len == 5 && memcmp(start, "allow", 5) == 0) return ALLOW;
    if (len == 5 && memcmp(start, "block", 5) == 0) return BLOCK;
    return BLOCK;
}

static enum strategy parse_strategy(char *start, size_t len)
{
    if (len == 4 && memcmp(start, "drop", 4) == 0) return STRATEGY_DROP;
    if (len == 3 && memcmp(start, "edt", 3) == 0) return STRATEGY_EDT;
    if (len == 3 && memcmp(start, "ecn", 3) == 0) return STRATEGY_ECN;
    return -1;
}

static int read_optional_strategy(char **pp, enum strategy *out)
{
    char *p = skip_ws(*pp);
    if (*p == '\0' || *p == '\n' || *p == '#')
        return 0;

    char *strat_start;
    size_t strat_len;
    p = read_token(p, &strat_start, &strat_len);
    enum strategy strat = parse_strategy(strat_start, strat_len);
    if ((int)strat < 0)
        return 0;

    *out = strat;
    *pp = p;
    return 1;
}

static int parse_one_rule(char *line, struct rule *out)
{
    char *p = skip_ws(line);
    if (*p == '\0' || *p == '#') return -1;

    char *comm_start;
    size_t comm_len;
    p = read_token(p, &comm_start, &comm_len);
    if (comm_len == 0) return -1;

    p = skip_ws(p);
    if (*p == '\0') return -1;

    char *endptr;
    long pct = strtol(p, &endptr, 10);
    if (endptr == p) return -1;
    p = endptr;

    p = skip_ws(p);
    if (*p == '\0') return -1;

    char *action_start;
    size_t action_len;
    p = read_token(p, &action_start, &action_len);

    enum action action = parse_action(action_start, action_len);

    enum strategy egr = DEFAULT_EGRESS_STRATEGY;
    enum strategy ingr = DEFAULT_INGRESS_STRATEGY;

    read_optional_strategy(&p, &egr);
    read_optional_strategy(&p, &ingr);

    out->comm = (char *)malloc(comm_len + 1);
    if (!out->comm) return -1;
    memcpy(out->comm, comm_start, comm_len);
    out->comm[comm_len] = '\0';
    out->bandwidth_pct = (int)pct;
    out->action = action;
    out->egress_strategy = egr;
    out->ingress_strategy = ingr;
    return 0;
}

static int parse_rules(const char *path, struct rule *out, int max_rules)
{
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;

    int count = 0;
    char *line = NULL;
    size_t len = 0;

    while (count < max_rules && getline(&line, &len, fp) != -1)
    {
        if (line[0] == '#' || line[0] == '\n') continue;
        if (parse_one_rule(line, &out[count]) == 0)
            count++;
    }

    free(line);
    fclose(fp);
    return count;
}

static const struct rule* match_rule(const struct rule *rules, int n, const char *comm)
{
    const struct rule *fallback = NULL;

    for (int i = 0; i < n; i++)
    {
        if (strcmp(rules[i].comm, comm) == 0)
            return &rules[i];
        if (strcmp(rules[i].comm, "*") == 0)
            fallback = &rules[i];
    }

    return fallback;
}

static void free_rules(struct rule *rules, int n)
{
    for (int i = 0; i < n; i++)
        free(rules[i].comm);
}

#endif
