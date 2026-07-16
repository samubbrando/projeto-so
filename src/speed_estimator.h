#ifndef SPEED_ESTIMATOR_H
#define SPEED_ESTIMATOR_H

#include <stdint.h>
#include <stdio.h>

struct speed_estimator {
    unsigned long long current_speed_bps;

    unsigned long long peak_observed_bps;
    unsigned long long prev_rx_bytes;
    unsigned long long prev_tx_bytes;
    uint64_t prev_time_ns;
    int calibrated;

    uint64_t last_active_test_ns;
    int active_test_enabled;
    int active_test_interval_s;

    int consecutive_idle_cycles;
    int idle_threshold_cycles;

    unsigned long long sysfs_speed_bps;
};

void speed_estimator_init(struct speed_estimator *estimator, const char* iface) {
    if (estimator == NULL) {
        return;
    }

    if (!estimator->calibrated) {
        char path[256];
        snprintf(path, sizeof(path), "/sys/class/net/%s/speed", iface);
        FILE *fp = fopen(path, "r");
        if (fp) {
            int speed;
            if (fscanf(fp, "%d", &speed) == 1) {
                estimator->sysfs_speed_bps = (unsigned long long)speed * 1000000ULL;
            }
            fclose(fp);
        }
    }
}

#endif