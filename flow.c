#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <math.h>
#include "flow.h"
#include "context.h"
#include "condition.h"
#include "log.h"

static void finalize_aggergration(apermon_context *ctx) {
    apermon_hash_item *aggr = ctx->aggr_hash->head;
    apermon_aggregated_flow *af;
    double tmp, exp_val;

    time_t dt = (ctx->now.tv_sec - ctx->last_aggregate.tv_sec) * 1000000 + (ctx->now.tv_usec - ctx->last_aggregate.tv_usec); // us

    if (dt < MIN_CALC_INTERVAL) {
        return;
    }

    tmp = -((double) dt) / 1000000 / RUNNING_AVERAGE_SIZE;
    exp_val = exp(tmp);

#ifdef APERMON_DEBUG
    log_debug("calculating running average, dt = %lu, exp_val = %f\n", dt, exp_val);
#endif

    while (aggr != NULL) {
        af = (apermon_aggregated_flow *) aggr->value;

#ifdef APERMON_DEBUG
        char addr[INET6_ADDRSTRLEN + 1];

        if (af->flow_af == SFLOW_AF_INET) {
            inet_ntop(AF_INET, &af->inet, addr, sizeof(addr));
        } else {
            inet_ntop(AF_INET6, af->inet6, addr, sizeof(addr));
        }

        log_debug("addr = %s\n", addr);
        log_debug("[1] in_bps = %lu, out_bps = %lu, in_pps = %lu, out_pps = %lu\n", af->in_bps, af->out_bps, af->in_pps, af->out_pps);
#endif

        tmp = ((double) af->current_in_pkts) * 1000000 / dt;
        af->in_pps = (uint64_t) (tmp + (exp_val * ((double) af->in_pps - tmp)));
        tmp = ((double) af->current_out_pkts) * 1000000 / dt;
        af->out_pps = (uint64_t) (tmp + (exp_val * ((double) af->out_pps - tmp)));
        tmp = ((double) af->current_in_bytes) * 8 * 1000000 / dt;
        af->in_bps = (uint64_t) (tmp + (exp_val * ((double) af->in_bps - tmp)));
        tmp = ((double) af->current_out_bytes) * 8 * 1000000 / dt;
        af->out_bps = (uint64_t) (tmp + (exp_val * ((double) af->out_bps - tmp)));
        
#ifdef APERMON_DEBUG
        log_debug("[2] in_bps = %lu, out_bps = %lu, in_pps = %lu, out_pps = %lu\n", af->in_bps, af->out_bps, af->in_pps, af->out_pps);
        log_debug("[current] in_b = %lu, out_b = %lu, in_p = %lu, out_p = %lu\n", af->current_in_bytes * 8, af->current_out_bytes * 8, af->current_in_pkts, af->current_out_pkts);
#endif

        af->current_in_pkts = af->current_out_pkts = 0;
        af->current_in_bytes = af->current_out_bytes = 0;

        aggr = aggr->iter_next;
    }

    ctx->last_aggregate = ctx->now;
}

static void add_contrib_flow(apermon_aggregated_flow *af, const apermon_flow_record *flow) {
    memcpy(&af->contrib_flows[af->contrib_flows_index], flow, sizeof(apermon_flow_record));
    af->contrib_flows_index = (af->contrib_flows_index + 1) % CONTRIB_TRACK_SIZE;
}

static apermon_aggregated_flow *aggergrate_flows_inet(apermon_context *ctx, uint32_t addr, const apermon_prefix *pfx, const apermon_flow_record *flow, uint8_t dir) {
    apermon_aggregated_flow *af, *oldval = NULL;
    uint32_t rate = flow->rate, cap = ctx->current_flows->agent->sample_rate_cap;
    uint32_t target = addr;

    if (ctx->trigger_config->aggregator == APERMON_AGGREGATOR_NET) {
        target = pfx->inet;
    }

    af = hash32_find(ctx->aggr_hash, &target);

    if (cap > 0 && flow->rate > cap) {
        rate = cap;
    }

    if (af == NULL) {
        af = new_aflow();
    }

    af->last_modified = ctx->now.tv_sec;
    af->flow_af = SFLOW_AF_INET;
    af->inet = target;
    af->prefix = pfx;

    if (dir == FLOW_INGRESS) {
        af->current_in_bytes += flow->frame_length * rate;
        af->current_in_pkts += rate;
    } else {
        af->current_out_bytes += flow->frame_length * rate;
        af->current_out_pkts += rate;
    }

    hash32_add_or_update(ctx->aggr_hash, &target, af, (void **) &oldval);

    if (oldval != af && oldval != NULL) {
        log_warn("internal error: apermon_aggregated_flow struct replaced in hash\n");
    }

    add_contrib_flow(af, flow);
    return af;
}

static apermon_aggregated_flow *aggergrate_flows_inet6(apermon_context *ctx, const uint8_t *addr, const apermon_prefix *pfx, const apermon_flow_record *flow, uint8_t dir) {
    apermon_aggregated_flow *af, *oldval = NULL;
    uint32_t rate = flow->rate, cap = ctx->current_flows->agent->sample_rate_cap;
    const uint8_t *target = addr;

    if (ctx->trigger_config->aggregator == APERMON_AGGREGATOR_NET) {
        target = pfx->inet6;
    }

    af = hash128_find(ctx->aggr_hash, target);

    if (cap > 0 && flow->rate > cap) {
        rate = cap;
    }

    if (af == NULL) {
        af = new_aflow();
    }

    af->last_modified = ctx->now.tv_sec;
    af->flow_af = SFLOW_AF_INET6;
    memcpy(af->inet6, target, sizeof(af->inet6));
    af->prefix = pfx;

    if (dir == FLOW_INGRESS) {
        af->current_in_bytes += flow->frame_length * rate;
        af->current_in_pkts += rate;
    } else {
        af->current_out_bytes += flow->frame_length * rate;
        af->current_out_pkts += rate;
    }

    hash128_add_or_update(ctx->aggr_hash, target, af, (void **) &oldval);

    if (oldval != af && oldval != NULL) {
        log_warn("internal error: apermon_aggregated_flow struct replaced in hash\n");
    }

    add_contrib_flow(af, flow);
    return af;
}

int aggergrate_flows(apermon_context *ctx) {
    const apermon_config_triggers *t = ctx->trigger_config;
    const apermon_flow_record *flow;
    const apermon_prefix *pfx;
    size_t i;
    uint8_t dir;

    for (i = 0; i < ctx->n_selected; ++i) {
        flow = ctx->selected_flows[i];
        dir = ctx->flow_directions[i];
        pfx = ctx->selected_prefixes[i];

        if (t->flags & APERMON_TRIGGER_CHECK_INGRESS && dir == FLOW_INGRESS) {
            if (flow->flow_af == SFLOW_AF_INET) {
                aggergrate_flows_inet(ctx, flow->dst_inet, pfx, flow, dir);
            } else if (flow->flow_af == SFLOW_AF_INET6) {
                aggergrate_flows_inet6(ctx, flow->dst_inet6, pfx, flow, dir);
            } else {
                log_error("internal error: bad af.\n");
            }
        } else if (t->flags & APERMON_TRIGGER_CHECK_EGRESS && dir == FLOW_EGRESS) {
            if (flow->flow_af == SFLOW_AF_INET) {
                aggergrate_flows_inet(ctx, flow->src_inet, pfx, flow, dir);
            } else if (flow->flow_af == SFLOW_AF_INET6) {
                aggergrate_flows_inet6(ctx, flow->src_inet6, pfx, flow, dir);
            } else {
                log_error("internal error: bad af.\n");
            }
        }
    }

    finalize_aggergration(ctx);

    return 0;
}

apermon_aggregated_flow *new_aflow() {
    apermon_aggregated_flow *af = (apermon_aggregated_flow *) malloc(sizeof(apermon_aggregated_flow));
    memset(af, 0, sizeof(apermon_aggregated_flow));

    return af;
}

void free_aflow(void *f) {
    apermon_aggregated_flow *flow = (apermon_aggregated_flow *) f;
    if (flow == NULL) {
        return;
    }

    free(flow);
}

void dump_flows(FILE *to, const apermon_context *ctx) {
    apermon_hash_item *aggr = ctx->aggr_hash->head;
    apermon_aggregated_flow *af;

    char addr[INET6_ADDRSTRLEN + 1];

    while (aggr != NULL) {
        af = (apermon_aggregated_flow *) aggr->value;

        if (ctx->now.tv_sec - af->last_modified > FLOW_DUMP_BACKTRACK) {
            aggr = aggr->iter_next;
            continue;
        }

        if (af->flow_af == SFLOW_AF_INET) {
            inet_ntop(AF_INET, &af->inet, addr, sizeof(addr));
        } else {
            inet_ntop(AF_INET6, af->inet6, addr, sizeof(addr));
        }

        if (ctx->trigger_config->aggregator == APERMON_AGGREGATOR_NET) {
            fprintf(to, "%s,%d,%u,%s/%u,%lu,%lu,%lu,%lu\n",
                ctx->trigger_config->name, ctx->trigger_config->aggregator, af->flow_af, addr, af->prefix->cidr, af->in_bps, af->out_bps, af->in_pps, af->out_pps
            );
        } else {
            fprintf(to, "%s,%d,%u,%s,%lu,%lu,%lu,%lu\n",
                ctx->trigger_config->name, ctx->trigger_config->aggregator, af->flow_af, addr, af->in_bps, af->out_bps, af->in_pps, af->out_pps
            );
        }

        aggr = aggr->iter_next;
    }
}