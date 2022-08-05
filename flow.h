#ifndef APERMON_FLOW_H
#define APERMON_FLOW_H
#include <stdint.h>

typedef struct _apermon_context apermon_context;

typedef struct _apermon_aggregated_flow {
    uint32_t flow_af; /* enum sflow_af */

    union {
        uint32_t inet;
        uint8_t inet6[16];
    };

    uint64_t bps;
    uint64_t pps;

    uint32_t last_uptime;
} apermon_aggregated_flow;

int aggergrate_flows(apermon_context *ctx);

#endif // APERMON_FLOW_H