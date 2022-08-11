#ifndef APERMON_FLOW_H
#define APERMON_FLOW_H
#include <stdint.h>
#include "hash.h"
#include "time.h"
#include "extract.h"

#define CONTRIB_TRACK_SIZE 100
#define MAX_RECORDS_PER_FLOW 1024
#define RUNNING_AVERAGE_SIZE 30
#define FLOW_DUMP_BACKTRACK 10

typedef struct _apermon_context apermon_context;
typedef struct _apermon_aggregated_flow apermon_aggregated_flow;

typedef struct _apermon_aggregated_agent_data {
    uint32_t last_uptime;

    uint64_t current_in_bytes, current_out_bytes;
    uint64_t current_in_pkts, current_out_pkts;

    size_t running_average_index;
    uint64_t in_bps[RUNNING_AVERAGE_SIZE], out_bps[RUNNING_AVERAGE_SIZE];
    uint64_t in_pps[RUNNING_AVERAGE_SIZE], out_pps[RUNNING_AVERAGE_SIZE];
} apermon_aggregated_agent_data;

typedef struct _apermon_aggregated_flow {
    int dirty;

    uint32_t flow_af; /* enum sflow_af */

    union {
        uint32_t inet;
        uint8_t inet6[16];
    };

    time_t last_modified;

    apermon_flow_record contrib_flows[CONTRIB_TRACK_SIZE];
    size_t contrib_flows_index;

    apermon_hash *agent_data; /* maps agent inet/inet6 to apermon_aggregated_agent_data */
} apermon_aggregated_flow;

typedef struct _apermon_aggregated_flow_average {
    uint64_t in_bps, out_bps;
    uint64_t in_pps, out_pps;
} apermon_aggregated_flow_average;

int aggergrate_flows(apermon_context *ctx);

apermon_aggregated_flow *new_aflow();
void free_aflow(void *flow);

apermon_aggregated_agent_data *new_agent_data();
void free_agent_data(apermon_aggregated_agent_data *data);

const apermon_aggregated_flow_average* running_average(const apermon_aggregated_flow *af); // not thread safe - uses local struct

void dump_flows(FILE *to, const apermon_context *ctx, int only_dirty);

#endif // APERMON_FLOW_H