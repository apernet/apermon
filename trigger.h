#ifndef APERMON_TRIGGER_H
#define APERMON_TRIGGER_H
#include "config.h"
#include "extract.h"
#include "flow.h"
#define APERMON_TRIGGER_FLAG_FIRED 0b00000001

typedef struct _apermon_trigger_state {
    uint8_t flags; /* APERMON_TRIGGER_FLAG_* */
    uint8_t aggregator; /* enum aggregator */
    uint8_t af; /* enum sflow_af */

    union {
        uint32_t inet; // if aggr = host/prefix
        uint8_t inet6[16]; // if aggr = host/prefix
        const apermon_config_prefix_lists *net; // if aggr = net
    };

    uint64_t peak_in_pps, peak_out_pps;
    uint64_t peak_in_bps, peak_out_bps;

    const apermon_config_prefix_lists *prefix_list; // always
    const apermon_prefix *prefix; // always

    const apermon_config_triggers *trigger; // not owned by us

    time_t last_triggered;
    time_t first_triggered;
} apermon_trigger_state;

void init_triggers(const apermon_config *config);
void triggers_timed_callback();
int run_trigger(const apermon_config_triggers *config, const apermon_flows *flows);

#endif // APERMON_TRIGGER_H