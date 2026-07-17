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

#define EST_DEFAULT_INTERVAL_S  5
#define EST_PACKET_SIZE       1460
#define EST_BURST_BYTES   (1024 * 1024)
#define EST_BURST_PKTS    (EST_BURST_BYTES / EST_PACKET_SIZE)  /* ~718 */

struct speed_estimator {
    unsigned long long current_speed_bps;
    unsigned long long peak_observed_bps;
    unsigned long long active_test_bps;
    unsigned long long sysfs_speed_bps;

    unsigned long long prev_egress_bytes;
    uint64_t prev_time_ns;

    int test_sock;
    struct sockaddr_in test_addr;
    uint64_t last_test_ns;
    int interval_s;
    char payload[EST_PACKET_SIZE];
};

void speed_estimator_init(struct speed_estimator *est, const char *iface) {
    memset(est, 0, sizeof(struct speed_estimator));

    est->test_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (est->test_sock < 0) 
        perror("speed_estimator: socket");

    est->test_addr.sin_family = AF_INET;
    est->test_addr.sin_port = htons(53);
    inet_pton(AF_INET, "8.8.8.8", &est->test_addr.sin_addr);

    est->interval_s = EST_DEFAULT_INTERVAL_S;

    char path[256];
    snprintf(path, sizeof(path), "/sys/class/net/%s/speed", iface);
    FILE *fp = fopen(path, "r");
    if (fp) {
        int speed;
        if (fscanf(fp, "%d", &speed) == 1 && speed > 0) {
            est->sysfs_speed_bps = (unsigned long long)speed * 1000000ULL;
        }
        fclose(fp);
    }

    for (int i = 0; i < (int)sizeof(est->payload); i++) {
        est->payload[i] = (char)(i % 256);
    }
}


void speed_estimator_update(struct speed_estimator *est,
                            unsigned long long (*read_egress)(void),
                            uint64_t now_ns);
unsigned long long speed_estimator_capacity(struct speed_estimator *est);
void speed_estimator_destroy(struct speed_estimator *est);

void speed_estimator_update(struct speed_estimator *est,
                            unsigned long long (*read_egress)(void),
                            uint64_t now_ns) {
    unsigned long long egress_bytes = read_egress();

    if (est->prev_time_ns == 0) {
        est->prev_egress_bytes = egress_bytes;
        est->prev_time_ns = now_ns;
        return;
    }

    unsigned long long delta_bytes = egress_bytes - est->prev_egress_bytes;
    unsigned long long delta_ns = now_ns - est->prev_time_ns;

    if (delta_ns > 0 && delta_bytes > 0) {
        unsigned long long real_bps = delta_bytes * 8000000000ULL / delta_ns;
        if (real_bps > est->peak_observed_bps)
            est->peak_observed_bps = real_bps;
    }

    if (now_ns - est->last_test_ns >= (uint64_t)est->interval_s * 1000000000ULL) {
        if (est->test_sock >= 0) {
            unsigned long long before = read_egress();

            struct timespec t0, t1;
            clock_gettime(CLOCK_MONOTONIC, &t0);

            for (int i = 0; i < EST_BURST_PKTS; i++) {
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

            if (test_ns > 50) {
                unsigned long long after = read_egress();
                unsigned long long test_bytes = after - before;
                unsigned long long test_bps = test_bytes * 8000000000ULL / test_ns;
                if (test_bps > est->active_test_bps)
                    est->active_test_bps = test_bps;
            }
        }
        est->last_test_ns = now_ns;
    }

    est->current_speed_bps = est->peak_observed_bps;
    if (est->active_test_bps > est->current_speed_bps)
        est->current_speed_bps = est->active_test_bps;
    if (est->sysfs_speed_bps > est->current_speed_bps)
        est->current_speed_bps = est->sysfs_speed_bps;

    est->prev_egress_bytes = egress_bytes;
    est->prev_time_ns = now_ns;
}

unsigned long long speed_estimator_capacity(struct speed_estimator *est) {
    return est->current_speed_bps;
}

void speed_estimator_destroy(struct speed_estimator *est) {
    if (est->test_sock >= 0)
        close(est->test_sock);
}

#endif