#ifndef APERMON_TRIGGER_H
#define APERMON_TRIGGER_H
#include "config.h"
#include "extract.h"
#include "flow.h"
#define TRIGGER_UNBAN_SCAN_INTERVAL 10 // seconds

typedef struct _apermon_trigger_state {
    uint8_t af; /* enum sflow_af */

    union {
        uint32_t inet;
        uint8_t inet6[16];
    };

    const apermon_config_triggers *trigger; // not owned by us

    time_t last_triggered;
    time_t first_triggered;
} apermon_trigger_state;

int run_trigger(const apermon_config_triggers *config, const apermon_flows *flows);

#endif // APERMON_TRIGGER_H