#ifndef APERMON_CONTEXT_H
#define APERMON_CONTEXT_H
#include "extract.h"
#include "hash.h"
#include "flow.h"
#include "config.h"
#include "condition.h"

typedef struct _apermon_context {
    // info about current batch of flow records
    const apermon_flows *current_flows;
    apermon_cond_func_list *selected_flows;

    // context (persistent) info
    apermon_hash *aggr_hash; /* hashmap: inet/inet6 to apermon_aggregated_flow */
    apermon_config_triggers *trigger_config;
} apermon_context;

#endif // APERMON_CONTEXT_H