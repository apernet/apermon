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

static apermon_aggregated_flow *aggergrate_one_flow(size_t i, const apermon_context *ctx, const hash_find_func find, const hash_add_or_update_func update, const void *key, size_t key_sz) {
    apermon_aggregated_flow *af, *oldval = NULL;

    const apermon_flow_record *flow = ctx->selected_flows[i];
    uint32_t rate = flow->rate, cap = ctx->current_flows->agent->sample_rate_cap;

    af = find(ctx->aggr_hash, key);

    if (cap > 0 && flow->rate > cap) {
        rate = cap;
    }

    if (af == NULL) {
        af = new_aflow();
    }

    af->last_modified = ctx->now.tv_sec;
    af->flow_af = flow->flow_af;
    af->prefix = ctx->selected_prefixes[i];
    af->aggregator = ctx->trigger_config->aggregator;

    if (ctx->flow_directions[i] == FLOW_INGRESS) {
        af->current_in_bytes += flow->frame_length * rate;
        af->current_in_pkts += rate;
    } else if (ctx->flow_directions[i] == FLOW_EGRESS) {
        af->current_out_bytes += flow->frame_length * rate;
        af->current_out_pkts += rate;
    } else {
        log_warn("internal error: invalid flow direction %u\n", ctx->flow_directions[i]);
    }

    // inet is locate at the start of union - type is not important, only need its address so this copy works
    memcpy(&af->inet, key, key_sz); 

    update(ctx->aggr_hash, key, af, (void **) &oldval);

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
    const apermon_config_prefix_lists *plist;
    const void *key;

    hash_find_func hash_find;
    hash_add_or_update_func hash_add_or_update;
    
    size_t i, key_sz;
    uint8_t dir;

    for (i = 0; i < ctx->n_selected; ++i) {
        flow = ctx->selected_flows[i];
        dir = ctx->flow_directions[i];
        pfx = ctx->selected_prefixes[i];
        plist = ctx->selected_prefixe_lists[i];
        
        // select hash key and hash fns
        if (t->aggregator == APERMON_AGGREGATOR_HOST) {
            hash_find = flow->flow_af == SFLOW_AF_INET ? hash32_find : hash128_find;
            hash_add_or_update = flow->flow_af == SFLOW_AF_INET ? hash32_add_or_update : hash128_add_or_update;

            if (t->flags & APERMON_TRIGGER_CHECK_INGRESS && dir == FLOW_INGRESS) {
                key = flow->flow_af == SFLOW_AF_INET ? (void *) &flow->dst_inet : (void *) flow->dst_inet6;
                key_sz = flow->flow_af == SFLOW_AF_INET ? sizeof(flow->dst_inet) : sizeof(flow->dst_inet6);
            } else if (t->flags & APERMON_TRIGGER_CHECK_EGRESS && dir == FLOW_EGRESS) {
                key = flow->flow_af == SFLOW_AF_INET ? (void *) &flow->dst_inet : (void *) flow->dst_inet6;
                key_sz = flow->flow_af == SFLOW_AF_INET ? sizeof(flow->dst_inet) : sizeof(flow->dst_inet6);
            } else {
                continue;
            }
        } else if (t->aggregator == APERMON_AGGREGATOR_PREFIX) {
            hash_find = pfx->af == SFLOW_AF_INET ? hash32_find : hash128_find;
            hash_add_or_update = pfx->af == SFLOW_AF_INET ? hash32_add_or_update : hash128_add_or_update;

            key = pfx->af == SFLOW_AF_INET ? (void *) &pfx->inet : (void *) pfx->inet6;
            key_sz = pfx->af == SFLOW_AF_INET ? sizeof(pfx->inet) : sizeof(pfx->inet6);
        } else if (t->aggregator == APERMON_AGGREGATOR_NET) {
            hash_find = hash_ptr_find;
            hash_add_or_update = hash_ptr_add_or_update;

            key = &plist;
            key_sz = hash_ptr_len;
        } else {
            log_error("internal error: bad aggregator %d.\n", t->aggregator);
            continue;
        }

        aggergrate_one_flow(i, ctx, hash_find, hash_add_or_update, key, key_sz);
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

        if (af->aggregator != APERMON_AGGREGATOR_NET) {
            if (af->flow_af == SFLOW_AF_INET) {
                inet_ntop(AF_INET, &af->inet, addr, sizeof(addr));
            } else {
                inet_ntop(AF_INET6, af->inet6, addr, sizeof(addr));
            }
        }

        if (af->aggregator == APERMON_AGGREGATOR_HOST) {
            fprintf(to, "%s,%d,%u,%s,%lu,%lu,%lu,%lu\n",
                ctx->trigger_config->name, ctx->trigger_config->aggregator, af->flow_af, addr, af->in_bps, af->out_bps, af->in_pps, af->out_pps
            );
        } else if (af->aggregator == APERMON_AGGREGATOR_PREFIX) {
            fprintf(to, "%s,%d,%u,%s/%u,%lu,%lu,%lu,%lu\n",
                ctx->trigger_config->name, ctx->trigger_config->aggregator, af->flow_af, addr, af->prefix->cidr, af->in_bps, af->out_bps, af->in_pps, af->out_pps
            );
        } else if (af->aggregator == APERMON_AGGREGATOR_NET) {
            fprintf(to, "%s,%d,%u,%s,%lu,%lu,%lu,%lu\n",
                ctx->trigger_config->name, ctx->trigger_config->aggregator, af->flow_af, af->net->name, af->in_bps, af->out_bps, af->in_pps, af->out_pps
            );
        }

        aggr = aggr->iter_next;
    }
}