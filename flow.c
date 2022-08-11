#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "flow.h"
#include "context.h"
#include "condition.h"
#include "log.h"

static apermon_aggregated_flow_average _running_average;

static void finalize_aggergration(apermon_aggregated_agent_data **as, size_t n, uint32_t now) {
    size_t i;
    uint32_t dt;
    apermon_aggregated_agent_data *af;

    for (i = 0; i < n; ++i) {
        af = as[i];
        af->in_bps[af->running_average_index] = 0;
        af->in_pps[af->running_average_index] = 0;
        af->out_bps[af->running_average_index] = 0;
        af->out_pps[af->running_average_index] = 0;
    }

    for (i = 0; i < n; ++i) {
        af = as[i];

        // uptime reseted - clear counter to re-calc
        if (af->last_uptime > now) {
            af->last_uptime = now;
            continue;
        }

        if (af->last_uptime == now) {
            log_debug("last update is the same as now - retr / replay attack?\n");
            return;
        }

        dt = now - af->last_uptime;
        af->in_pps[af->running_average_index] += af->current_in_pkts * 1000 / dt;
        af->in_bps[af->running_average_index] += af->current_in_bytes * 8 * 1000 / dt;
        af->out_pps[af->running_average_index] += af->current_out_pkts * 1000 / dt;
        af->out_bps[af->running_average_index] += af->current_out_bytes * 8 * 1000 / dt;

        af->current_in_pkts = 0;
        af->current_in_bytes = 0;
        af->current_out_pkts = 0;
        af->current_out_bytes = 0;
    }

    for (i = 0; i < n; ++i) {
        if (af->last_uptime != now) {
            af->last_uptime = now;
            af->running_average_index = (af->running_average_index + 1) % RUNNING_AVERAGE_SIZE;
        }
    }
}

static apermon_aggregated_agent_data *aggergrate_update_agent_data(const apermon_flows *flows, apermon_hash *agent_hash, uint64_t current_bytes, uint64_t current_pkts, uint8_t dir) {
    apermon_aggregated_agent_data *ad, *oldval = NULL;

    if (flows->agent_af == SFLOW_AF_INET) {
        ad = hash32_find(agent_hash, &flows->agent_inet);
    } else if (flows->agent_af == SFLOW_AF_INET) {
        ad = hash128_find(agent_hash, flows->agent_inet6);
    } else {
        log_error("bad agent af %d\n", flows->agent_af);
        return NULL;
    }

    if (ad == NULL) {
        ad = new_agent_data();
    }

    if (dir == FLOW_INGRESS) {
        ad->current_in_bytes += current_bytes;
        ad->current_in_pkts += current_pkts;
    } else {
        ad->current_out_bytes += current_bytes;
        ad->current_out_pkts += current_pkts;
    }

    if (flows->agent_af == SFLOW_AF_INET) {
        hash32_add_or_update(agent_hash, &flows->agent_inet, ad, (void **) &oldval);
    } else if (flows->agent_af == SFLOW_AF_INET) {
        hash128_add_or_update(agent_hash, flows->agent_inet6, ad, (void **) &oldval);
    } 

    if (oldval != ad && oldval != NULL) {
        log_warn("internal error: apermon_aggregated_agent_data struct replaced in hash\n");
    }

    return ad;
}

static void add_contrib_flow(apermon_aggregated_flow *af, const apermon_flow_record *flow) {
    memcpy(&af->contrib_flows[af->contrib_flows_index], flow, sizeof(apermon_flow_record));
    af->contrib_flows_index = (af->contrib_flows_index + 1) % CONTRIB_TRACK_SIZE;
}

static apermon_aggregated_agent_data *aggergrate_flows_host_inet(apermon_context *ctx, uint32_t addr, const apermon_flow_record *flow, uint8_t dir) {
    apermon_aggregated_flow *af = hash32_find(ctx->aggr_hash, &addr), *oldval = NULL;
    uint32_t rate = flow->rate, cap = ctx->current_flows->agent->sample_rate_cap;

    if (cap > 0 && flow->rate > cap) {
        rate = cap;
    }

    if (af == NULL) {
        af = new_aflow();
    }

    af->last_modified = ctx->now;
    af->dirty = 1;
    af->flow_af = SFLOW_AF_INET;
    af->inet = addr;

    hash32_add_or_update(ctx->aggr_hash, &addr, af, (void **) &oldval);

    if (oldval != af && oldval != NULL) {
        log_warn("internal error: apermon_aggregated_flow struct replaced in hash\n");
    }

    add_contrib_flow(af, flow);
    return aggergrate_update_agent_data(ctx->current_flows, af->agent_data, flow->frame_length * rate, rate, dir);
}

static apermon_aggregated_agent_data *aggergrate_flows_host_inet6(apermon_context *ctx, const uint8_t *addr, const apermon_flow_record *flow, uint8_t dir) {
    apermon_aggregated_flow *af = hash128_find(ctx->aggr_hash, addr), *oldval = NULL;
    uint32_t rate = flow->rate, cap = ctx->current_flows->agent->sample_rate_cap;

    if (cap > 0 && flow->rate > cap) {
        rate = cap;
    }

    if (af == NULL) {
        af = new_aflow();
    }

    af->last_modified = ctx->now;
    af->dirty = 1;
    af->flow_af = SFLOW_AF_INET6;
    memcpy(af->inet6, addr, sizeof(af->inet6));

    hash128_add_or_update(ctx->aggr_hash, addr, af, (void **) &oldval);

    if (oldval != af && oldval != NULL) {
        log_warn("internal error: apermon_aggregated_flow struct replaced in hash\n");
    }

    add_contrib_flow(af, flow);
    return aggergrate_update_agent_data(ctx->current_flows, af->agent_data, flow->frame_length * rate, rate, dir);
}

static int aggergrate_flows_host(apermon_context *ctx) {
    const apermon_config_triggers *t = ctx->trigger_config;
    const apermon_flow_record *flow;
    size_t n_modified = 0, i;
    uint8_t dir;
    uint32_t now = ctx->current_flows->uptime; // unit: ms

    apermon_aggregated_agent_data *modifed_flows[MAX_RECORDS_PER_FLOW];

    for (i = 0; i < ctx->n_selected; ++i) {
        flow = ctx->selected_flows[i];
        dir = ctx->flow_directions[i];

        if (t->flags & APERMON_TRIGGER_CHECK_INGRESS && dir == FLOW_INGRESS) {
            if (flow->flow_af == SFLOW_AF_INET) {
                modifed_flows[n_modified++] = aggergrate_flows_host_inet(ctx, flow->dst_inet, flow, dir);
            } else if (flow->flow_af == SFLOW_AF_INET6) {
                modifed_flows[n_modified++] = aggergrate_flows_host_inet6(ctx, flow->dst_inet6, flow, dir);
            } else {
                log_error("internal error: bad af.\n");
            }
        } else if (t->flags & APERMON_TRIGGER_CHECK_EGRESS && dir == FLOW_EGRESS) {
            if (flow->flow_af == SFLOW_AF_INET) {
                modifed_flows[n_modified++] = aggergrate_flows_host_inet(ctx, flow->src_inet, flow, dir);
            } else if (flow->flow_af == SFLOW_AF_INET6) {
                modifed_flows[n_modified++] = aggergrate_flows_host_inet6(ctx, flow->src_inet6, flow, dir);
            } else {
                log_error("internal error: bad af.\n");
            }
        }

        if (n_modified >= MAX_RECORDS_PER_FLOW) {
            log_warn("too many records to aggergrate in one sample - max %d allowed. rests will be ignored.\n", MAX_RECORDS_PER_FLOW);
            break;
        }
    }

    finalize_aggergration(modifed_flows, n_modified, now);

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
    af->agent_data = new_hash(4);

    return af;
}

void free_aflow(void *f) {
    apermon_aggregated_flow *flow = (apermon_aggregated_flow *) f;
    if (flow == NULL) {
        return;
    }

    free_hash(flow->agent_data, free);
    free(flow);
}

apermon_aggregated_agent_data *new_agent_data() {
    apermon_aggregated_agent_data *ad = (apermon_aggregated_agent_data *) malloc(sizeof(apermon_aggregated_agent_data));
    memset(ad, 0, sizeof(apermon_aggregated_agent_data));

    return ad;
}

void free_agent_data(apermon_aggregated_agent_data *data) {
    if (data == NULL) {
        return;
    }

    free(data);
}

const apermon_aggregated_flow_average *running_average(const apermon_aggregated_flow *af) {
    size_t i = 0, data_count = 0;
    const apermon_hash_item *a = af->agent_data->head;
    const apermon_aggregated_agent_data *ad;

    _running_average.in_bps = _running_average.out_bps = 0;
    _running_average.in_pps = _running_average.out_pps = 0;

    while (a != NULL) {
        ad = (const apermon_aggregated_agent_data *) a->value;
        for (i = 0; i < RUNNING_AVERAGE_SIZE; ++i) {
            _running_average.in_bps += ad->in_bps[i];
            _running_average.out_bps += ad->out_bps[i];
            _running_average.in_pps += ad->in_pps[i];
            _running_average.out_pps += ad->out_pps[i];
        }

        data_count += RUNNING_AVERAGE_SIZE;
        a = a->next;
    }

    _running_average.in_bps /= data_count;
    _running_average.out_bps /= data_count;
    _running_average.in_pps /= data_count;
    _running_average.out_pps /= data_count;

    return &_running_average;
}

void dump_flows(const apermon_context *ctx, int only_dirty) {
    apermon_hash_item *aggr = ctx->aggr_hash->head;
    apermon_aggregated_flow *af;
    apermon_flow_record *fr;
    size_t i;
    const apermon_aggregated_flow_average *avg;

    char addr[INET6_ADDRSTRLEN + 1], addr2[INET6_ADDRSTRLEN + 1];

    while (aggr != NULL) {
        af = (apermon_aggregated_flow *) aggr->value;

        if (ctx->now - af->last_modified > FLOW_DUMP_BACKTRACK || (only_dirty && !af->dirty)) {
            aggr = aggr->iter_next;
            continue;
        }

        if (af->flow_af == SFLOW_AF_INET) {
            inet_ntop(AF_INET, &af->inet, addr, sizeof(addr));
        } else {
            inet_ntop(AF_INET6, af->inet6, addr, sizeof(addr));
        }

        avg = running_average(af);

        log_info("instance %s, submmited by %s for %s: %lu bps in, %lu bps out, %lu pps in, %lu pps out\n",
            ctx->trigger_config->name, ctx->current_flows->agent->name, addr,
            avg->in_bps, avg->out_bps, avg->in_pps, avg->out_pps
        );

        for (i = 0; i < CONTRIB_TRACK_SIZE; ++i) {
            fr = &af->contrib_flows[i];

            if (fr->flow_af == SFLOW_AF_UNDEFINED) {
                // likely contrib_flows list does not have CONTRIB_TRACK_SIZE elements yet
                break;
            }

            if (fr->flow_af == SFLOW_AF_INET) {
                inet_ntop(AF_INET, &fr->src_inet, addr, sizeof(addr));
                inet_ntop(AF_INET, &fr->dst_inet, addr2, sizeof(addr2));
            } else {
                inet_ntop(AF_INET6, fr->src_inet6, addr, sizeof(addr));
                inet_ntop(AF_INET6, fr->dst_inet6, addr2, sizeof(addr2));
            }

            log_info("contrib flow proto %u, %s.%u -> %s.%u, %u bytes, %u pkts\n",
                fr->l3_proto, addr, fr->src_port, addr2, fr->dst_port, fr->frame_length * fr->rate, fr->rate
            );
        }

        aggr = aggr->iter_next;
    }
}