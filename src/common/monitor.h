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
    STRATEGY_ECN,
};

enum action
{
    ALLOW,
    BLOCK,
};

struct flow_key
{
    unsigned int src_ip;
    unsigned int dst_ip;
    unsigned short src_port;
    unsigned short dst_port;
    unsigned char protocol;
};

struct flow_key_v6
{
    unsigned char src_ip[16];
    unsigned char dst_ip[16];
    unsigned short src_port;
    unsigned short dst_port;
    unsigned char protocol;
};

struct flow_info
{
    unsigned char action;
    unsigned char egress_strategy;
    unsigned char ingress_strategy;
    unsigned int rate_bps;
};

struct block_entry
{
    unsigned char action;
    unsigned char ingress_strategy;
    unsigned int rate_bps;
};


#endif
