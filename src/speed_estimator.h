#ifndef SPEED_ESTIMATOR_H
#define SPEED_ESTIMATOR_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "common/monitor.h"

#define EST_DEFAULT_INTERVAL_S 5
#define EST_PACKET_SIZE 1460
#define EST_BURST_BYTES (1024 * 1024)
#define EST_BURST_PKTS (EST_BURST_BYTES / EST_PACKET_SIZE)
#define EST_WINDOW_SIZE 8

#ifndef SO_MARK
#define SO_MARK 36
#endif

struct speed_estimator
{
    unsigned long long override_bps;
    unsigned long long current_speed_bps;
    unsigned long long active_test_bps;
    unsigned long long sysfs_speed_bps;

    uint64_t prev_time_ns;

    int test_sock;
    struct sockaddr_in test_addr;
    uint64_t last_test_ns;
    int interval_s;
    char payload[EST_PACKET_SIZE];

    char iface[64];
    unsigned long long prev_tx_bytes;

    unsigned long long samples[EST_WINDOW_SIZE];
    int sample_head;
    int n_samples;
};

void speed_estimator_init(struct speed_estimator *est, const char *iface)
{
    memset(est, 0, sizeof(struct speed_estimator));

    strncpy(est->iface, iface, sizeof(est->iface) - 1);
    est->prev_tx_bytes = 0;

    est->test_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (est->test_sock < 0)
        perror("speed_estimator: socket");

    est->test_addr.sin_family = AF_INET;
    est->test_addr.sin_port = htons(53);
    inet_pton(AF_INET, "8.8.8.8", &est->test_addr.sin_addr);

    if (setsockopt(est->test_sock, SOL_SOCKET, SO_MARK, &(int){PROBE_FWMARK}, sizeof(int)) < 0)
        perror("speed_estimator: setsockopt");

    est->interval_s = EST_DEFAULT_INTERVAL_S;

    const char *override = getenv("CAPACITY_BPS");
    if (override && override[0])
    {
        est->override_bps = strtoull(override, NULL, 10);
        fprintf(stderr, "speed_estimator: capacity overridden by CAPACITY_BPS=%llu bps\n",
                est->override_bps);
    }

    char path[256];
    snprintf(path, sizeof(path), "/sys/class/net/%s/speed", iface);
    FILE *fp = fopen(path, "r");
    if (fp)
    {
        int speed;
        if (fscanf(fp, "%d", &speed) == 1 && speed > 0)
        {
            est->sysfs_speed_bps = (unsigned long long)speed * 1000000ULL;
        }
        fclose(fp);
    }

    for (int i = 0; i < (int)sizeof(est->payload); i++)
    {
        est->payload[i] = (char)(i % 256);
    }
}

static unsigned long long read_tx_bytes(const char *iface)
{
    char path[256];
    snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/tx_bytes", iface);
    FILE *fp = fopen(path, "r");
    if (!fp)
        return 0;
    unsigned long long val = 0;
    fscanf(fp, "%llu", &val);
    fclose(fp);
    return val;
}

void speed_estimator_update(struct speed_estimator *est,
                            uint64_t now_ns)
{
    if (est->override_bps > 0)
        return;

    if (est->prev_time_ns == 0)
    {
        est->prev_time_ns = now_ns;
        return;
    }

    unsigned long long curr = read_tx_bytes(est->iface);
    if (est->prev_tx_bytes > 0 && curr >= est->prev_tx_bytes)
    {
        unsigned long long delta = curr - est->prev_tx_bytes;
        uint64_t dt = now_ns - est->prev_time_ns;
        if (dt > 0)
            est->current_speed_bps =
                (unsigned long long)((double)delta * 8.0e9 / (double)dt);
    }
    est->prev_tx_bytes = curr;

    if (now_ns - est->last_test_ns >= (uint64_t)est->interval_s * 1000000000ULL)
    {
        if (est->test_sock >= 0)
        {
            unsigned long long before = read_tx_bytes(est->iface);

            struct timespec t0, t1;
            clock_gettime(CLOCK_MONOTONIC, &t0);

            for (int i = 0; i < EST_BURST_PKTS; i++)
            {
                ssize_t ret = sendto(est->test_sock, est->payload, EST_PACKET_SIZE,
                                     0, (struct sockaddr *)&est->test_addr,
                                     sizeof(est->test_addr));
                if (ret < 0)
                    break;
            }

            clock_gettime(CLOCK_MONOTONIC, &t1);

            unsigned long long test_ns =
                (t1.tv_sec - t0.tv_sec) * 1000000000ULL +
                (t1.tv_nsec - t0.tv_nsec);

            if (test_ns > 50)
            {
                unsigned long long after = read_tx_bytes(est->iface);
                unsigned long long test_bytes = after - before;
                unsigned long long test_bps = test_bytes * 8000000000ULL / test_ns;
                est->active_test_bps = test_bps;

                if (test_bytes >= EST_BURST_BYTES / 2)
                {
                    est->samples[est->sample_head % EST_WINDOW_SIZE] = test_bps;
                    est->sample_head++;
                    if (est->n_samples < EST_WINDOW_SIZE)
                        est->n_samples++;
                }
            }
        }
        est->last_test_ns = now_ns;
    }

    est->prev_time_ns = now_ns;
}

static int comp_bps(const void *a, const void *b)
{
    unsigned long long x = *(const unsigned long long *)a;
    unsigned long long y = *(const unsigned long long *)b;
    return (x > y) - (x < y);
}

unsigned long long speed_estimator_capacity(struct speed_estimator *est)
{
    if (est->override_bps > 0)
        return est->override_bps;

    int minimum = 3;

    if (est->n_samples >= minimum)
    {
        unsigned long long tmp[EST_WINDOW_SIZE];
        memcpy(tmp, est->samples, sizeof(est->samples));
        qsort(tmp, est->n_samples, sizeof(unsigned long long), comp_bps);
        return tmp[est->n_samples / 2];
    }
    else if (est->n_samples > 0)
    {
        return est->samples[est->n_samples - 1];
    }

    if (est->sysfs_speed_bps > 0)
        return est->sysfs_speed_bps;

    return est->current_speed_bps;
}

void speed_estimator_destroy(struct speed_estimator *est)
{
    if (est->test_sock >= 0)
        close(est->test_sock);
}

#endif