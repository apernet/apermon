#ifndef APERMON_FLOW_H
#define APERMON_FLOW_H
#include <stdint.h>
#include "hash.h"
#include "condition.h"
#include "context.h"

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

enum aggergrate_direction {
    APERMON_AGGR_INGRESS,
    APERMON_AGGR_EGRESS,
};

apermon_aggregated_flow *aggergrate_flow(apermon_context *ctx, const apermon_sflow_record *record);

#endif // APERMON_FLOW_H