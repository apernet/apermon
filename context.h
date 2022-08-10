#ifndef APERMON_CONTEXT_H
#define APERMON_CONTEXT_H
#include "extract.h"
#include "hash.h"
#include "flow.h"
#include "config.h"
#include "time.h"

#define CONTEXT_GC_MIN_INTERVAL 10 // wait at least 10s before each gc
#define CONTEXT_GC_STALE_TIME 30 // entries not updated in 30s are removed

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
    apermon_hash *trigger_status; /* hashmap: inet/inet6 to trigger status, owned by us */
    apermon_config_triggers *trigger_config; /* not own by us */
    time_t now;
    time_t last_gc;
} apermon_context;

apermon_context *new_context();
void free_context(apermon_context *ctx);
void gc_context(apermon_context *ctx);

#endif // APERMON_CONTEXT_H