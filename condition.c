#include <string.h>
#include <stdlib.h>
#include "prefix-list.h"
#include "condition.h"
#include "log.h"

static apermon_context *_ctx;

int cond_list(const apermon_flow_record* record, const void* arg /* apermon_cond_list* */) {
    const apermon_cond_list *cl = (apermon_cond_list *) arg;
    const apermon_cond_func_list *f = cl->funcs;

    if (cl->type == APERMON_COND_AND) {
        while (f != NULL) {
            if (!f->func(record, f->arg)) {
                return 0;
            }

            f = f->next;
        }

        return 1;
    } else if (cl->type == APERMON_COND_OR) {
        while (f != NULL) {
            if (f->func(record, f->arg)) {
                return 1;
            }

            f = f->next;
        }

        return 0;
    } else if (cl->type == APERMON_COND_NOT) {
        while (f != NULL) {
            if (f->func(record, f->arg)) {
                return 0;
            }

            f = f->next;
        }

        return 1;
    } else {
        log_error("unknown cond type %d.\n", cl->type);
    }

    return 0;
}

int cond_in_interface(const apermon_flow_record* record, const void* arg /* apermon_config_interfaces** */) {
    apermon_config_interfaces *iface = *(apermon_config_interfaces **) arg;
    apermon_config_ifindexes *ifindex = iface->ifindexes;
    while (ifindex != NULL) {
        if (strcmp(ifindex->agent->name, _ctx->current_flows->agent_name) != 0) {
            ifindex = ifindex->next;
            continue;
        }

        if (ifindex->ifindex == record->in_ifindex) {
            return 1;
        }

        ifindex = ifindex->next;
    }

    return 0;
}

int cond_out_interface(const apermon_flow_record* record, const void* arg /* apermon_config_interfaces** */) {
    apermon_config_interfaces *iface = *(apermon_config_interfaces **) arg;
    apermon_config_ifindexes *ifindex = iface->ifindexes;
    while (ifindex != NULL) {
        if (strcmp(ifindex->agent->name, _ctx->current_flows->agent_name) != 0) {
            ifindex = ifindex->next;
            continue;
        }

        if (ifindex->ifindex == record->out_ifindex) {
            return 1;
        }

        ifindex = ifindex->next;
    }

    return 0;
}

int cond_src(const apermon_flow_record* record, const void* arg /* apermon_config_prefix_list_elements** */) {
    const apermon_config_prefix_list_elements *l = *(apermon_config_prefix_list_elements **) arg;

    if (record->flow_af == SFLOW_AF_INET) {
        return apermon_prefix_list_match_inet(l, record->src_inet);
    } else if (record->flow_af == SFLOW_AF_INET6) {
        return apermon_prefix_list_match_inet6(l, record->src_inet6);
    } 

    log_error("unknown flow address family %d.\n", record->flow_af);

    return 0;
}

int cond_dst(const apermon_flow_record* record, const void* arg /* apermon_config_prefix_list_elements** */) {
    const apermon_config_prefix_list_elements *l = *(apermon_config_prefix_list_elements **) arg;

    if (record->flow_af == SFLOW_AF_INET) {
        return apermon_prefix_list_match_inet(l, record->dst_inet);
    } else if (record->flow_af == SFLOW_AF_INET6) {
        return apermon_prefix_list_match_inet6(l, record->dst_inet6);
    } 

    log_error("unknown flow address family %d.\n", record->flow_af);

    return 0;
}

int cond_proto(const apermon_flow_record* record, const void* arg /* uint8_t* */) {
    return (* (uint8_t *) arg) == record->l3_proto;
}

int cond_src_port(const apermon_flow_record* record, const void* arg /* uint16_t* */) {
    return (* (uint16_t *) arg) == record->src_port;
}

int cond_dst_port(const apermon_flow_record* record, const void* arg /* uint16_t* */) {
    return (* (uint16_t *) arg) == record->dst_port;
}

void cond_begin(apermon_context *ctx) {
    _ctx = ctx;
}

void select_flow(const apermon_flow_record *flow) {
    const apermon_config_triggers *t = _ctx->trigger_config;
    const apermon_config_prefix_lists_set *ls = t->networks;
    const apermon_config_prefix_list_elements *ps;

    while (ls != NULL) {
        ps = ls->prefix_list->elements;

        if (flow->flow_af == SFLOW_AF_INET) {
            if ((t->flags & APERMON_TRIGGER_CHECK_INGRESS) && apermon_prefix_list_match_inet(ps, flow->dst_inet)) {
                _ctx->flow_directions[_ctx->n_selected] = FLOW_INGRESS;
                _ctx->selected_flows[_ctx->n_selected] = flow;
                _ctx->n_selected++;
                break;
            } else if ((t->flags & APERMON_TRIGGER_CHECK_EGRESS) && apermon_prefix_list_match_inet(ps, flow->src_inet)) {
                _ctx->flow_directions[_ctx->n_selected] = FLOW_EGRESS;
                _ctx->selected_flows[_ctx->n_selected] = flow;
                _ctx->n_selected++;
                break;
            }
        } else if (flow->flow_af == SFLOW_AF_INET6) {
            if ((t->flags & APERMON_TRIGGER_CHECK_INGRESS) && apermon_prefix_list_match_inet6(ps, flow->dst_inet6)) {
                _ctx->flow_directions[_ctx->n_selected] = FLOW_INGRESS;
                _ctx->selected_flows[_ctx->n_selected] = flow;
                _ctx->n_selected++;
                break;
            } else if ((t->flags & APERMON_TRIGGER_CHECK_EGRESS) && apermon_prefix_list_match_inet6(ps, flow->src_inet6)) {
                _ctx->flow_directions[_ctx->n_selected] = FLOW_EGRESS;
                _ctx->selected_flows[_ctx->n_selected] = flow;
                _ctx->n_selected++;
                break;
            }
        } else {
            log_error("bad af: %d\n", flow->flow_af);
        }

        ls = ls->next;
    }
}
