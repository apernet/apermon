#ifndef APERMON_FLOW_H
#define APERMON_FLOW_H
#include <stdint.h>
#include "hash.h"

#define MAX_RECORDS_PER_FLOW 1024
#define RUNNING_AVERAGE_SIZE 10

typedef struct _apermon_context apermon_context;
typedef struct _apermon_aggregated_flow apermon_aggregated_flow;

typedef struct _apermon_aggregated_agent_data {
    uint32_t last_uptime;

    uint64_t current_bytes;
    uint64_t current_pkts;

    size_t running_average_index;
    uint64_t bps[RUNNING_AVERAGE_SIZE];
    uint64_t pps[RUNNING_AVERAGE_SIZE];
} apermon_aggregated_agent_data;

typedef struct _apermon_aggregated_flow {
    int dirty;

    uint32_t flow_af; /* enum sflow_af */

    union {
        uint32_t inet;
        uint8_t inet6[16];
    };

    apermon_hash *agent_data; /* maps agent inet/inet6 to apermon_aggregated_agent_data */
} apermon_aggregated_flow;

int aggergrate_flows(apermon_context *ctx);

apermon_aggregated_flow *new_aflow();
void free_aflow(void *flow);

apermon_aggregated_agent_data *new_agent_data();
void free_agent_data(apermon_aggregated_agent_data *data);

uint64_t running_average_bps(const apermon_aggregated_flow *af);
uint64_t running_average_pps(const apermon_aggregated_flow *af);

void dump_flows(const apermon_context *ctx);

#endif // APERMON_FLOW_H