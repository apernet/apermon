#include <string.h>
#include <stdlib.h>
#include "prefix-list.h"
#include "condition.h"
#include "log.h"

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

int cond_in_interface(const apermon_flow_record* record, const void* arg /* apermon_config_interface** */) {
    // todo
    return 0;
}

int cond_out_interface(const apermon_flow_record* record, const void* arg /* apermon_config_interface** */) {
    // todo
    return 0;
}

int cond_src(const apermon_flow_record* record, const void* arg /* apermon_config_prefix_list_elements** */) {
    const apermon_config_prefix_list_elements *l = *(apermon_config_prefix_list_elements **) arg;
    const apermon_prefix *p;

    while (l != NULL) {
        p = l->prefix;
        if (p->af != record->flow_af) {
            l = l->next;
            continue;
        }

        if (p->af == SFLOW_AF_INET) {
            if (p->inet == record->src_inet) {
                return 1;
            }
        } else if (p->af == SFLOW_AF_INET6) {
            if (memcmp(p->inet6, record->src_inet6, sizeof(p->inet6)) == 0) {
                return 1;
            }
        } else {
            log_warn("internal error: unknown af %u.\n", p->af);
        }

        l = l->next;
    }

    return 0;
}

int cond_dst(const apermon_flow_record* record, const void* arg /* apermon_config_prefix_list_elements** */) {
    const apermon_config_prefix_list_elements *l = *(apermon_config_prefix_list_elements **) arg;
    const apermon_prefix *p;

    while (l != NULL) {
        p = l->prefix;
        if (p->af != record->flow_af) {
            l = l->next;
            continue;
        }

        if (p->af == SFLOW_AF_INET) {
            if (p->inet == record->dst_inet) {
                return 1;
            }
        } else if (p->af == SFLOW_AF_INET6) {
            if (memcmp(p->inet6, record->dst_inet6, sizeof(p->inet6)) == 0) {
                return 1;
            }
        } else {
            log_warn("internal error: unknown af %u.\n", p->af);
        }

        l = l->next;
    }

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

void select_flow(apermon_context *ctx, const apermon_flow_record *flow) {
    const apermon_config_triggers *t = ctx->trigger_config;
    const apermon_config_prefix_lists_set *ls = t->networks;
    const apermon_config_prefix_list_elements *ps;

    while (ls != NULL) {
        ps = ls->prefix_list->elements;

        if (flow->flow_af == SFLOW_AF_INET) {
            if ((t->flags & APERMON_TRIGGER_CHECK_INGRESS) && apermon_prefix_list_match_inet(ps, flow->dst_inet)) {
                ctx->flow_directions[ctx->n_selected] = FLOW_INGRESS;
                ctx->selected_flows[ctx->n_selected] = flow;
                ctx->n_selected++;
            } else if ((t->flags & APERMON_TRIGGER_CHECK_EGRESS) && apermon_prefix_list_match_inet(ps, flow->src_inet)) {
                ctx->flow_directions[ctx->n_selected] = FLOW_EGRESS;
                ctx->selected_flows[ctx->n_selected] = flow;
                ctx->n_selected++;
            }
        } else if (flow->flow_af == SFLOW_AF_INET6) {
            if ((t->flags & APERMON_TRIGGER_CHECK_INGRESS) && apermon_prefix_list_match_inet6(ps, flow->dst_inet6)) {
                ctx->flow_directions[ctx->n_selected] = FLOW_INGRESS;
                ctx->selected_flows[ctx->n_selected] = flow;
                ctx->n_selected++;
            } else if ((t->flags & APERMON_TRIGGER_CHECK_EGRESS) && apermon_prefix_list_match_inet6(ps, flow->src_inet6)) {
                ctx->flow_directions[ctx->n_selected] = FLOW_EGRESS;
                ctx->selected_flows[ctx->n_selected] = flow;
                ctx->n_selected++;
            }
        } else {
            log_error("bad af: %d\n", flow->flow_af);
        }

        ls = ls->next;
    }
}
