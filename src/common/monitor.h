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

#endif
