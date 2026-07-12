#ifndef HIST_H
#define HIST_H

struct conn_key
{
    unsigned short src_port;
    unsigned int src_ip;
    unsigned short dst_port;
    unsigned int dst_ip;
};

struct hist
{
    unsigned int rtt;
    unsigned long long sent;
    unsigned long long received;
};

#endif
