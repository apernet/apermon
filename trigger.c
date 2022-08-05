#include "trigger.h"
#include "context.h"
#include "log.h"
#include "flow.h"
#include "condition.h"

int init_trigger(apermon_config_triggers *config) {
    // todo
    return -1;
}

int run_trigger(const apermon_config_triggers *config, const apermon_flows *flows) {
    apermon_context *ctx = config->ctx;
    
    ctx->current_flows = flows;

    const apermon_flow_record *r = flows->records;

    while (r != NULL) {
        r = r->next;

        if (cond_list(r, config->conds)) {
            select_flow(ctx, r);
        }
    }

    if (aggergrate_flows(ctx) < 0) {
        log_warn("internal error: aggergrate_flows failed.\n");
    }

    free_selected_flows(ctx);

    return 0;
}