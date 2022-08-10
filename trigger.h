#ifndef APERMON_TRIGGER_H
#define APERMON_TRIGGER_H
#include "config.h"
#include "extract.h"
#include "flow.h"

typedef struct _apermon_trigger_state {
    uint8_t af; /* enum sflow_af */

    union {
        uint32_t inet;
        uint8_t inet6[16];
    };

    time_t triggered_on;
} apermon_trigger_state;

int run_trigger(const apermon_config_triggers *config, const apermon_flows *flows);
void fire_trigger(const apermon_config_triggers *config, const apermon_aggregated_flow *flow, const apermon_aggregated_flow_average *metrics);

#endif // APERMON_TRIGGER_H