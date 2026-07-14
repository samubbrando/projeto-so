#ifndef MONITOR_H
#define MONITOR_H

struct ingress_stats
{
    unsigned long long bytes;
    unsigned long long packets;
};

struct egress_stats
{
    unsigned long long bytes;
    unsigned long long packets;
};

struct flow_key
{
    unsigned int src_ip;
    unsigned int dst_ip;
    unsigned short src_port;
    unsigned short dst_port;
    unsigned char protocol;
};

struct rate_bucket
{
    unsigned long long tokens;
    unsigned long long last_ns;
    unsigned int rate_bps;
    unsigned int burst;
};

enum strategy
{
    STRATEGY_DROP,
    STRATEGY_EDT,
};

enum action
{
    ACTION_ALLOW,
    ACTION_BLOCK,
    ACTION_LIMIT,
};

struct flow_info
{
    unsigned char action;
    unsigned char strategy;
    unsigned int rate_bps;
};

struct block_entry
{
    unsigned char action;
    unsigned char strategy;
    unsigned int rate_bps;
};

#endif
