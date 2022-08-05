#ifndef APERMON_FLOW_H
#define APERMON_FLOW_H
#include <stdint.h>

#define MAX_RECORDS_PER_FLOW 1024
#define RUNNING_AVERAGE_SIZE 10

typedef struct _apermon_context apermon_context;

typedef struct _apermon_aggregated_flow {
    uint32_t flow_af; /* enum sflow_af */

    union {
        uint32_t inet;
        uint8_t inet6[16];
    };

    size_t running_average_index;
    uint64_t bps[RUNNING_AVERAGE_SIZE];
    uint64_t pps[RUNNING_AVERAGE_SIZE];

    uint32_t last_uptime;

    uint64_t current_bytes;
    uint64_t current_pkts;
} apermon_aggregated_flow;

int aggergrate_flows(apermon_context *ctx);
apermon_aggregated_flow *new_aflow();
void free_aflow(apermon_aggregated_flow *flow);

uint64_t running_average_bps(const apermon_aggregated_flow *af);
uint64_t running_average_pps(const apermon_aggregated_flow *af);

#endif // APERMON_FLOW_H