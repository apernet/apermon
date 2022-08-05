#include "condition.h"
#include "log.h"

int cond_list(apermon_context *ctx, const apermon_flow_record* record, const void* arg /* apermon_cond_list* */) {
    const apermon_cond_list *cl = arg;
    const apermon_cond_func_list *f = cl->funcs;

    if (cl->type == APERMON_COND_AND) {
        while (f != NULL) {
            if (!f->func(ctx, record, f->arg)) {
                return 0;
            }

            f = f->next;
        }

        return 1;
    } else if (cl->type == APERMON_COND_OR) {
        while (f != NULL) {
            if (f->func(ctx, record, f->arg)) {
                return 1;
            }

            f = f->next;
        }

        return 0;
    } else if (cl->type == APERMON_COND_NOT) {
        while (f != NULL) {
            if (f->func(ctx, record, f->arg)) {
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
