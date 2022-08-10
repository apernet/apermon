#ifndef APERMON_CONTEXT_H
#define APERMON_CONTEXT_H
#include "extract.h"
#include "hash.h"
#include "flow.h"
#include "config.h"

typedef struct _apermon_cond_selected_flows apermon_cond_selected_flows;

enum flow_direction {
    FLOW_INGRESS,
    FLOW_EGRESS,
};

typedef struct _apermon_context {
    // info about current batch of flow records
    const apermon_flows *current_flows; /* not own by us */
    const apermon_flow_record *selected_flows[MAX_RECORDS_PER_FLOW]; /* not own by us */
    
    uint8_t flow_directions[MAX_RECORDS_PER_FLOW];
    size_t n_selected;

    // context (persistent) info
    apermon_hash *aggr_hash; /* hashmap: inet/inet6 to aggr, own by us */
    apermon_config_triggers *trigger_config; /* not own by us */
} apermon_context;

apermon_context *new_context();
void free_context(apermon_context *ctx);

#endif // APERMON_CONTEXT_H