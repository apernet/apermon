#ifndef APERMON_FLOW_H
#define APERMON_FLOW_H
#include <stdint.h>
#include "hash.h"
#include "time.h"
#include "extract.h"

#define CONTRIB_TRACK_SIZE 100
#define MAX_RECORDS_PER_FLOW 1024
#define RUNNING_AVERAGE_SIZE 10
#define FLOW_DUMP_BACKTRACK 10
#define MIN_CALC_INTERVAL 1000000 // us

typedef struct _apermon_context apermon_context;
typedef struct _apermon_aggregated_flow apermon_aggregated_flow;

typedef struct _apermon_aggregated_flow {
    uint32_t flow_af; /* enum sflow_af */

    union {
        uint32_t inet;
        uint8_t inet6[16];
    };

    const apermon_prefix *prefix;
    uint64_t current_in_bytes, current_out_bytes;
    uint64_t current_in_pkts, current_out_pkts;

    uint64_t in_bps, out_bps;
    uint64_t in_pps, out_pps;

    time_t last_modified;

    apermon_flow_record contrib_flows[CONTRIB_TRACK_SIZE];
    size_t contrib_flows_index;
} apermon_aggregated_flow;

int aggergrate_flows(apermon_context *ctx);

apermon_aggregated_flow *new_aflow();
void free_aflow(void *flow);

void dump_flows(FILE *to, const apermon_context *ctx);

#endif // APERMON_FLOW_H