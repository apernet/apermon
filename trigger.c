#include "trigger.h"
#include "context.h"
#include "log.h"
#include "flow.h"
#include "condition.h"

int run_trigger(const apermon_config_triggers *config, const apermon_flows *flows) {
    apermon_context *ctx = config->ctx;
    apermon_hash_item *aggr;
    apermon_aggregated_flow *af;

    ctx->current_flows = flows;
    ctx->n_selected = 0;

    const apermon_flow_record *r = flows->records;

    cond_begin(ctx);

    while (r != NULL) {
        if (config->conds == NULL || cond_list(r, config->conds)) {
            select_flow(r);
        }

        r = r->next;
    }

    if (aggergrate_flows(ctx) < 0) {
        log_warn("internal error: aggergrate_flows failed.\n");
    }

    aggr = ctx->aggr_hash->head;
    while (aggr != NULL) {
        af = (apermon_aggregated_flow *) aggr->value;

        if (!af->dirty) {
            aggr = aggr->iter_next;
            continue;
        }

        af->dirty = 0;


        char addr[INET6_ADDRSTRLEN + 1];
        if (flows->agent_af == SFLOW_AF_INET) {
            inet_ntop(AF_INET, &af->inet, addr, sizeof(addr));
        } else {
            inet_ntop(AF_INET6, af->inet6, addr, sizeof(addr));
        }

        // todo GC: remove old aggregated flows not recently used

        log_debug("%s: %lu bps, %lu pps\n", addr, running_average_bps(af), running_average_pps(af));

        aggr = aggr->iter_next;
    }

    return 0;
}