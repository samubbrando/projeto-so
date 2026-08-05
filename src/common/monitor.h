#ifndef MONITOR_H
#define MONITOR_H

#define PROBE_FWMARK 0x2525

#define FLOW_FAMILY_IPV4 2
#define FLOW_FAMILY_IPV6 10

struct traffic_stats
{
    unsigned long long bytes;
    unsigned long long packets;
};

struct rate_bucket
{
    unsigned long long tokens;
    unsigned long long last_ns;
    unsigned long long rate_bps;
    unsigned long long burst;
};

enum strategy
{
    STRATEGY_DROP,
    STRATEGY_EDT,
    STRATEGY_ECN,
};

enum action
{
    ALLOW,
    BLOCK,
};

struct flow_key
{
    unsigned char family;
    unsigned char protocol;
    unsigned short src_port;
    unsigned short dst_port;
    union
    {
        unsigned int ip4[2];
        unsigned char ip6[32];
    } addr;
};

struct flow_policy
{
    unsigned char action;
    unsigned char strategy;
    unsigned long long rate_bps;
};

#endif
