#ifndef HIST_H
#define HIST_H

struct conn_key
{
    unsigned short src_port;
    unsigned int src_ip;
    unsigned short dst_port;
    unsigned int dst_ip;
    unsigned char protocol;
} __attribute__((packed));

struct hist
{
    unsigned int rtt;
    unsigned long long sent;
    unsigned long long received;
};

struct udp_stat
{
    unsigned long long tx_bytes;
    unsigned long long rx_bytes;
};

#endif
