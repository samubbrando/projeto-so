#ifndef HIST_H
#define HIST_H

struct conn_key
{
    unsigned short src_port;
    unsigned short dst_port;
    unsigned char  protocol;
    unsigned char  family;
    unsigned char  src_ip[16];
    unsigned char  dst_ip[16];
} __attribute__((packed));

struct hist
{
    unsigned int rtt;
    unsigned long long tx_bytes;
    unsigned long long rx_bytes;
    unsigned long long prev_msr;
};

#endif
