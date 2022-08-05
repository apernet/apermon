#include <string.h>
#include <stdlib.h>
#include "apermon.h"
#include "condition.h"
#include "log.h"

int cond_list(const apermon_flow_record* record, const void* arg /* apermon_cond_list* */) {
    const apermon_cond_list *cl = arg;
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

int cond_interface(const apermon_flow_record* record, const void* arg /* apermon_interface* */) {
    // todo
    return 0;
}

int cond_src(const apermon_flow_record* record, const void* arg /* apermon_pfx_list* */) {
    const apermon_prefix_list *l = arg;

    while (l != NULL) {
        if (l->af != record->flow_af) {
            continue;
        }

        if (l->af == SFLOW_AF_INET) {
            if (l->inet == record->src_inet) {
                return 1;
            }
        } else if (l->af == SFLOW_AF_INET6) {
            if (memcmp(l->inet6, record->src_inet6, sizeof(l->inet6)) == 0) {
                return 1;
            }
        } else {
            log_warn("internal error: unknown af %u.\n", l->af);
        }

        l = l->next;
    }

    return 0;
}

int cond_dst(const apermon_flow_record* record, const void* arg /* apermon_pfx_list* */) {
    const apermon_prefix_list *l = arg;

    while (l != NULL) {
        if (l->af != record->flow_af) {
            continue;
        }

        if (l->af == SFLOW_AF_INET) {
            if (l->inet == record->dst_inet) {
                return 1;
            }
        } else if (l->af == SFLOW_AF_INET6) {
            if (memcmp(l->inet6, record->dst_inet6, sizeof(l->inet6)) == 0) {
                return 1;
            }
        } else {
            log_warn("internal error: unknown af %u.\n", l->af);
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
    apermon_cond_selected_flows *s = (apermon_cond_selected_flows *) malloc(sizeof(apermon_cond_selected_flows));
    s->flow = flow;
    s->next = NULL;

    if (ctx->selected_flows_tail == NULL) {
        ctx->selected_flows_tail = ctx->selected_flows = s;
    } else {
        ctx->selected_flows_tail->next = s;
    }
}

void free_selected_flows(apermon_context *ctx) {
    apermon_cond_selected_flows *s = ctx->selected_flows, *prev = NULL;

    while (s != NULL) {
        if (prev == NULL) {
            free(prev);
        }

        prev = s;
        s = s->next;
    }

    if (prev == NULL) {
        free(prev);
    }
}