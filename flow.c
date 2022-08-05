#include <stdlib.h>
#include <string.h>
#include "flow.h"
#include "context.h"
#include "condition.h"
#include "log.h"

static void finalize_aggergration(apermon_aggregated_flow **as, size_t n, uint32_t now) {
    size_t i;
    uint32_t dt;
    apermon_aggregated_flow *af;

    for (i = 0; i < n; ++i) {
        af = as[i];

        // uptime reseted - clear counter to re-calc
        if (af->last_uptime > now) {
            af->last_uptime = now;
            continue;
        }

        dt = now - af->last_uptime;
        af->pps[af->running_average_index] += af->current_pkts * 1000 / dt;
        af->bps[af->running_average_index] += af->current_bytes * 8 * 1000 / dt;
    }

    for (i = 0; i < n; ++i) {
        if (af->last_uptime != now) {
            af->last_uptime = now;
            ++af->running_average_index;
            af->running_average_index = af->running_average_index % RUNNING_AVERAGE_SIZE;
        }
    }
}

static void check_trigger(const apermon_config_triggers *t, apermon_aggregated_flow **fs, size_t n) {
    // debug only now - prints aggr'd flows

    size_t i;
    apermon_aggregated_flow *flow;

    for (i = 0; i < n; ++i) {
        flow = fs[i];
        if (flow->flow_af == SFLOW_AF_INET) {
            log_debug("%u: %lu bps, %lu pps\n", flow->inet, running_average_bps(flow), running_average_pps(flow));
        }
    }
}

static apermon_aggregated_flow *aggergrate_flows_host_inet(apermon_hash *ah, uint32_t addr, const apermon_flow_record *flow) {
    apermon_aggregated_flow *a = (apermon_aggregated_flow *) hash32_find(ah, &addr), *oldval = NULL;

    if (a == NULL) {
        a = new_aflow();
    }

    a->flow_af = SFLOW_AF_INET;
    a->inet = addr;
    a->current_bytes += flow->frame_length * flow->rate;
    a->current_pkts += flow->rate;

    hash32_add_or_update(ah, &addr, a, (void **) &oldval);

    if (oldval != a && oldval != NULL) {
        log_warn("internal error: apermon_aggregated_flow struct replaced in hash\n");
    }

    return a;
}

static apermon_aggregated_flow *aggergrate_flows_host_inet6(apermon_hash *ah, const uint8_t *addr, const apermon_flow_record *flow) {
    apermon_aggregated_flow *a = (apermon_aggregated_flow *) hash128_find(ah, addr), *oldval = NULL;

    if (a == NULL) {
        a = new_aflow();
    }

    a->flow_af = SFLOW_AF_INET6;
    a->current_bytes += flow->frame_length * flow->rate;
    a->current_pkts += flow->rate;
    memcpy(a->inet6, addr, sizeof(a->inet6));

    hash128_add_or_update(ah, addr, a, (void **) &oldval);

    if (oldval != a && oldval != NULL) {
        log_warn("internal error: apermon_aggregated_flow struct replaced in hash\n");
    }

    return a;
}

static int aggergrate_flows_host(apermon_context *ctx) {
    const apermon_config_triggers *t = ctx->trigger_config;
    const apermon_cond_selected_flows *f = ctx->selected_flows;
    const apermon_flow_record *flow;

    apermon_aggregated_flow *modifed_flows[MAX_RECORDS_PER_FLOW];
    size_t n_modified = 0;

    uint32_t now = ctx->current_flows->uptime; // unit: ms

    while (f != NULL) {
        flow = f->flow;

        if (t->flags & APERMON_TRIGGER_CHECK_INGRESS) {
            if (flow->flow_af == SFLOW_AF_INET) {
                modifed_flows[n_modified++] = aggergrate_flows_host_inet(ctx->aggr_hash, flow->dst_inet, flow);
            } else if (flow->flow_af == SFLOW_AF_INET6) {
                modifed_flows[n_modified++] = aggergrate_flows_host_inet6(ctx->aggr_hash, flow->dst_inet6, flow);
            } else {
                log_error("internal error: bad af.\n");
            }
        } else if (t->flags & APERMON_TRIGGER_CHECK_EGRESS) {
            if (flow->flow_af == SFLOW_AF_INET) {
                modifed_flows[n_modified++] = aggergrate_flows_host_inet(ctx->aggr_hash, flow->src_inet, flow);
            } else if (flow->flow_af == SFLOW_AF_INET6) {
                modifed_flows[n_modified++] = aggergrate_flows_host_inet6(ctx->aggr_hash, flow->src_inet6, flow);
            } else {
                log_error("internal error: bad af.\n");
            }
        } else {
            log_warn("no directions defined for trigger %s - no triggering will happen.\n", t->name);
        }

        if (n_modified >= MAX_RECORDS_PER_FLOW) {
            log_warn("too many records to aggergrate in one sample - max %d allowed. rests will be ignored.\n", MAX_RECORDS_PER_FLOW);
            break;
        }

        f = f->next;
    }

    finalize_aggergration(modifed_flows, n_modified, now);
    check_trigger(t, modifed_flows, n_modified);

    return 0;
}

static int aggergrate_flows_net(apermon_context *ctx) {
    // todo
    return -1;
}

int aggergrate_flows(apermon_context *ctx) {
    const apermon_config_triggers *t = ctx->trigger_config;

    int ret = -1;

    if (t->aggregator == APERMON_AGGREGATOR_HOST) {
        ret = aggergrate_flows_host(ctx);
    } else if (t->aggregator == APERMON_AGGREGATOR_NET) {
        ret = aggergrate_flows_net(ctx);
    } else {
        log_error("internal error: unknown aggregator %d\n", ctx->trigger_config->aggregator);
    }

    if (ret < 0) {
        log_error("internal error: failed to aggergrate_flows.\n");
    }

    return ret;
}

apermon_aggregated_flow *new_aflow() {
    apermon_aggregated_flow *af = (apermon_aggregated_flow *) malloc(sizeof(apermon_aggregated_flow));
    memset(af, 0, sizeof(apermon_aggregated_flow));

    return af;
}

void free_aflow(apermon_aggregated_flow *flow) {
    free(flow);
}

uint64_t running_average_bps(const apermon_aggregated_flow *af) {
    uint64_t sum = 0;
    size_t i = 0;

    for (i = 0; i < RUNNING_AVERAGE_SIZE; ++i) {
        sum += af->bps[i];
    }

    return sum / RUNNING_AVERAGE_SIZE;
}

uint64_t running_average_pps(const apermon_aggregated_flow *af) {
    uint64_t sum = 0;
    size_t i = 0;

    for (i = 0; i < RUNNING_AVERAGE_SIZE; ++i) {
        sum += af->pps[i];
    }

    return sum / RUNNING_AVERAGE_SIZE;
}