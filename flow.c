#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "flow.h"
#include "context.h"
#include "condition.h"
#include "log.h"

static apermon_aggregated_flow_average _running_average;

static void finalize_aggergration(apermon_context *ctx) {
    apermon_hash_item *aggr = ctx->aggr_hash->head;
    apermon_aggregated_flow *af;

    time_t dt = (ctx->now.tv_sec - ctx->last_aggregate.tv_sec) * 1000000 + (ctx->now.tv_usec - ctx->last_aggregate.tv_usec); // us

    while (aggr != NULL) {
        af = (apermon_aggregated_flow *) aggr->value;

        af->in_pps -= (af->in_pps / RUNNING_AVERAGE_SIZE);
        af->out_pps -= (af->out_pps / RUNNING_AVERAGE_SIZE);
        af->in_bps -= (af->in_bps / RUNNING_AVERAGE_SIZE);
        af->out_bps -= (af->out_bps / RUNNING_AVERAGE_SIZE);

        af->in_pps += af->current_in_pkts * 1000000 / dt / RUNNING_AVERAGE_SIZE;
        af->in_bps += af->current_in_bytes * 8 * 1000000 / dt / RUNNING_AVERAGE_SIZE;
        af->out_pps += af->current_out_pkts * 1000000 / dt / RUNNING_AVERAGE_SIZE;
        af->out_bps += af->current_out_bytes * 8 * 1000000 / dt / RUNNING_AVERAGE_SIZE;

        af->current_in_pkts = af->current_out_bytes = 0;
        af->current_in_bytes = af->current_out_bytes = 0;

        af->running_average_index = (af->running_average_index + 1) % RUNNING_AVERAGE_SIZE;

        aggr = aggr->next;
    }

    ctx->last_aggregate = ctx->now;
}

static void add_contrib_flow(apermon_aggregated_flow *af, const apermon_flow_record *flow) {
    memcpy(&af->contrib_flows[af->contrib_flows_index], flow, sizeof(apermon_flow_record));
    af->contrib_flows_index = (af->contrib_flows_index + 1) % CONTRIB_TRACK_SIZE;
}

static apermon_aggregated_flow *aggergrate_flows_host_inet(apermon_context *ctx, uint32_t addr, const apermon_flow_record *flow, uint8_t dir) {
    apermon_aggregated_flow *af = hash32_find(ctx->aggr_hash, &addr), *oldval = NULL;
    uint32_t rate = flow->rate, cap = ctx->current_flows->agent->sample_rate_cap;

    if (cap > 0 && flow->rate > cap) {
        rate = cap;
    }

    if (af == NULL) {
        af = new_aflow();
    }

    af->last_modified = ctx->now.tv_sec;
    af->flow_af = SFLOW_AF_INET;
    af->inet = addr;

    if (dir == FLOW_INGRESS) {
        af->current_in_bytes += flow->frame_length * rate;
        af->current_in_pkts += rate;
    } else {
        af->current_out_bytes += flow->frame_length * rate;
        af->current_out_pkts += rate;
    }

    hash32_add_or_update(ctx->aggr_hash, &addr, af, (void **) &oldval);

    if (oldval != af && oldval != NULL) {
        log_warn("internal error: apermon_aggregated_flow struct replaced in hash\n");
    }

    add_contrib_flow(af, flow);
    return af;
}

static apermon_aggregated_flow *aggergrate_flows_host_inet6(apermon_context *ctx, const uint8_t *addr, const apermon_flow_record *flow, uint8_t dir) {
    apermon_aggregated_flow *af = hash128_find(ctx->aggr_hash, addr), *oldval = NULL;
    uint32_t rate = flow->rate, cap = ctx->current_flows->agent->sample_rate_cap;

    if (cap > 0 && flow->rate > cap) {
        rate = cap;
    }

    if (af == NULL) {
        af = new_aflow();
    }

    af->last_modified = ctx->now.tv_sec;
    af->flow_af = SFLOW_AF_INET6;
    memcpy(af->inet6, addr, sizeof(af->inet6));
    if (dir == FLOW_INGRESS) {
        af->current_in_bytes += flow->frame_length * rate;
        af->current_in_pkts += rate;
    } else {
        af->current_out_bytes += flow->frame_length * rate;
        af->current_out_pkts += rate;
    }

    hash128_add_or_update(ctx->aggr_hash, addr, af, (void **) &oldval);

    if (oldval != af && oldval != NULL) {
        log_warn("internal error: apermon_aggregated_flow struct replaced in hash\n");
    }

    add_contrib_flow(af, flow);
    return af;
}

static int aggergrate_flows_host(apermon_context *ctx) {
    const apermon_config_triggers *t = ctx->trigger_config;
    const apermon_flow_record *flow;
    size_t i;
    uint8_t dir;

    for (i = 0; i < ctx->n_selected; ++i) {
        flow = ctx->selected_flows[i];
        dir = ctx->flow_directions[i];

        if (t->flags & APERMON_TRIGGER_CHECK_INGRESS && dir == FLOW_INGRESS) {
            if (flow->flow_af == SFLOW_AF_INET) {
                aggergrate_flows_host_inet(ctx, flow->dst_inet, flow, dir);
            } else if (flow->flow_af == SFLOW_AF_INET6) {
                aggergrate_flows_host_inet6(ctx, flow->dst_inet6, flow, dir);
            } else {
                log_error("internal error: bad af.\n");
            }
        } else if (t->flags & APERMON_TRIGGER_CHECK_EGRESS && dir == FLOW_EGRESS) {
            if (flow->flow_af == SFLOW_AF_INET) {
                aggergrate_flows_host_inet(ctx, flow->src_inet, flow, dir);
            } else if (flow->flow_af == SFLOW_AF_INET6) {
                aggergrate_flows_host_inet6(ctx, flow->src_inet6, flow, dir);
            } else {
                log_error("internal error: bad af.\n");
            }
        }
    }

    finalize_aggergration(ctx);

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
        log_error("internal error: unknown aggregator %d in trigger %s\n", ctx->trigger_config->aggregator, ctx->trigger_config->name);
    }

    if (ret < 0) {
        log_error("internal error: aggergrate_flows failed (trigger: %s).\n", ctx->trigger_config->name);
    }

    return ret;
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

const apermon_aggregated_flow_average *running_average(const apermon_aggregated_flow *af) {
    size_t i = 0;

    _running_average.in_bps = af->in_bps;
    _running_average.out_bps = af->out_bps;
    _running_average.in_pps = af->in_pps;
    _running_average.out_pps = af->out_pps;

    return &_running_average;
}

void dump_flows(FILE *to, const apermon_context *ctx) {
    apermon_hash_item *aggr = ctx->aggr_hash->head;
    apermon_aggregated_flow *af;
    const apermon_aggregated_flow_average *avg;

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

        avg = running_average(af);

        fprintf(to, "%s,%s,%lu,%lu,%lu,%lu\n",
            ctx->trigger_config->name, addr, avg->in_bps, avg->out_bps, avg->in_pps, avg->out_pps
        );

        aggr = aggr->iter_next;
    }
}