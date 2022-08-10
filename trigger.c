#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include "trigger.h"
#include "context.h"
#include "log.h"
#include "flow.h"
#include "condition.h"
#include "net.h"
#include "prefix-list.h"

static void run_trigger_script_ban(const apermon_config_triggers *config, const apermon_config_action_scripts *script, const apermon_aggregated_flow *flow, const apermon_aggregated_flow_average *metrics) {
    char **argv = calloc(2, sizeof(char *));
    char **envp = calloc(10, sizeof(char *));
    char strbuf[0xffff], addr[INET6_ADDRSTRLEN + 1], addr2[INET6_ADDRSTRLEN + 1];

    const apermon_config_prefix_lists_set *set = config->networks;
    const apermon_config_prefix_lists *l = NULL;
    const apermon_config_prefix_list_elements *el = NULL;
    const apermon_prefix *pfx = NULL;
    const apermon_flow_record *fr;

    int offset = 0, i, ret;

    stop_servers(1); // closes fds in fork

    argv[0] = script->name;
    argv[1] = NULL;

    snprintf(strbuf, sizeof(strbuf), "AF=%u", flow->flow_af);
    envp[0] = strdup(strbuf);

    if (flow->flow_af == SFLOW_AF_INET) {
        inet_ntop(AF_INET, &flow->inet, addr, sizeof(addr));
    } else {
        inet_ntop(AF_INET6, flow->inet6, addr, sizeof(addr));
    }

    snprintf(strbuf, sizeof(strbuf), "ADDR=%s", addr);
    envp[1] = strdup(strbuf);

    while (set != NULL) {
        l = set->prefix_list;
        el = l->elements;

        while (el != NULL) {
            pfx = el->prefix;

            if (pfx->af != flow->flow_af) {
                el = el->next;
                continue;
            }

            if (pfx->af == SFLOW_AF_INET) {
                if (apermon_prefix_match_inet(pfx, flow->inet)) {
                    snprintf(strbuf, sizeof(strbuf), "NET=%s", l->name);
                    envp[2] = strdup(strbuf);

                    inet_ntop(AF_INET, &pfx->inet, addr, sizeof(addr));
                    inet_ntop(AF_INET, &pfx->mask, addr2, sizeof(addr2));

                    snprintf(strbuf, sizeof(strbuf), "PREFIX=%s/%s", addr, addr2);
                    envp[3] = strdup(strbuf);
                    goto end_net_and_prefix;
                }
            } else {
                if (apermon_prefix_match_inet6(pfx, flow->inet6)) {
                    snprintf(strbuf, sizeof(strbuf), "NET=%s", l->name);
                    envp[2] = strdup(strbuf);

                    inet_ntop(AF_INET6, pfx->inet6, addr, sizeof(addr));
                    inet_ntop(AF_INET6, pfx->mask6, addr2, sizeof(addr2));
                    snprintf(strbuf, sizeof(strbuf), "PREFIX=%s/%s", addr, addr2);
                    envp[3] = strdup(strbuf);
                    goto end_net_and_prefix;
                }
            }

            el = el->next;
        }

        set = set->next;
    }

end_net_and_prefix:
    snprintf(strbuf, sizeof(strbuf), "IN_BPS=%lu", metrics->in_bps);
    envp[4] = strdup(strbuf);

    snprintf(strbuf, sizeof(strbuf), "OUT_BPS=%lu", metrics->out_bps);
    envp[5] = strdup(strbuf);

    snprintf(strbuf, sizeof(strbuf), "IN_PPS=%lu", metrics->in_pps);
    envp[6] = strdup(strbuf);

    snprintf(strbuf, sizeof(strbuf), "OUT_PPS=%lu", metrics->out_pps);
    envp[7] = strdup(strbuf);

    offset += snprintf(strbuf, sizeof(strbuf), "FLOWS=af,in_ifindex,out_ifindex,src,dst,proto,sport,dport,bytes,packets\n");

    for (i = 0; i < CONTRIB_TRACK_SIZE; ++i) {
        fr = &flow->contrib_flows[i];

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

        offset += snprintf(strbuf + offset, sizeof(strbuf) - offset, "%u,%u,%u,%s,%s,%u,%u,%u,%u,%u\n",
            fr->flow_af, fr->in_ifindex, fr->out_ifindex, addr, addr2, fr->l3_proto,
            fr->src_port, fr->dst_port, fr->frame_length * fr->rate, fr->rate
        );

        if ((size_t) offset >= sizeof(strbuf)) {
            log_warn("contrib_flows list too long, truncating\n");
            break;
        }
    }

    envp[8] = strdup(strbuf);
    envp[9] = NULL;

    ret = execve(script->name, argv, envp);

    if (ret < 0) {
        log_error("execve(): %s\n", strerror(errno));
    }
}

int run_trigger(const apermon_config_triggers *config, const apermon_flows *flows) {
    apermon_context *ctx = config->ctx;
    apermon_hash_item *aggr;
    apermon_aggregated_flow *af;
    uint64_t bps, pps;

    const apermon_flow_record *r = flows->records;
    const apermon_aggregated_flow_average *avg;

    ctx->now = time(NULL);
    ctx->current_flows = flows;
    ctx->n_selected = 0;

    if (ctx->now - ctx->last_gc >= CONTEXT_GC_MIN_INTERVAL) {
        gc_context(ctx);
    }

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

    dump_flows(ctx, 1);

    while (aggr != NULL) {
        af = (apermon_aggregated_flow *) aggr->value;

        if (!af->dirty) {
            aggr = aggr->iter_next;
            continue;
        }

        af->dirty = 0;
        avg = running_average(af);
        
        bps = avg->in_bps > avg->out_bps ? avg->in_bps : avg->out_bps;
        pps = avg->in_pps > avg->out_pps ? avg->in_pps : avg->out_pps;

        if (config->bps > 0) {
            if (bps >= config->bps) {
                fire_trigger(config, af, avg);
            }
        } else if (config->pps > 0) {
            if (pps >= config->pps) {
                fire_trigger(config, af, avg);
            }
        }

        aggr = aggr->iter_next;
    }

    return 0;
}

void fire_trigger(const apermon_config_triggers *config, const apermon_aggregated_flow *flow, const apermon_aggregated_flow_average *metrics) {
    log_debug("trigger %s fired - in_bps %lu, out_bps %lu, in_pps %lu, out_pps %lu\n", config->name, metrics->in_bps, metrics->out_bps, metrics->in_pps, metrics->out_pps);
    apermon_trigger_state *ts = NULL, *old_ts = NULL;
    const apermon_context *ctx = config->ctx;
    const apermon_config_actions *action = config->action;
    const apermon_config_action_scripts *script = action->scripts;
    pid_t pid;

    if (flow->flow_af == SFLOW_AF_INET) {
        ts = hash32_find(ctx->trigger_status, &flow->inet);
    } else {
        ts = hash128_find(ctx->trigger_status, flow->inet6);
    }

    if (ts == NULL) {
        ts = (apermon_trigger_state *) malloc(sizeof(apermon_trigger_state));
        memset(ts, 0, sizeof(apermon_trigger_state));
    }

    ts->af = flow->flow_af;
    ts->triggered_on = ctx->now;

    if (flow->flow_af == SFLOW_AF_INET) {
        ts->inet = flow->inet;
        hash32_add_or_update(ctx->trigger_status, &ts->inet, ts, (void **) &old_ts);
    } else {
        memcpy(ts->inet6, flow->inet6, sizeof(ts->inet6));
        hash128_add_or_update(ctx->trigger_status, ts->inet6, ts, (void **) &old_ts);
    }

    if (old_ts != ts && old_ts != NULL) {
        log_warn("internal error: apermon_trigger_state struct replaced in hash\n");
    }

    if (old_ts != NULL) {
        // old trigger status is not null - meaning last trigger has not been unfired yet, don't run action.
        log_debug("trigger '%s' has not been unfired since last fired, not running action.\n", config->name);
        return;
    }

    if (action == NULL) {
        log_warn("triggered '%s' fired but no action configured\n", config->name);
        return;
    }

    if (script == NULL) {
        log_warn("triggered '%s' fired but no action script configured in action '%s'\n", config->name, action->name);
        return;
    }

    while (script != NULL) {
        pid = fork();

        if (pid < 0) {
            log_error("fork(): %s\n", strerror(errno));
        }

        if (pid == 0) {
            run_trigger_script_ban(config, script, flow, metrics);
            log_error("run_trigger_script_ban returned - exiting\n");
            exit(0);
        }

        script = script->next;
    }
}