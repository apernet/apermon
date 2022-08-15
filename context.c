#include <string.h>
#include <stdlib.h>
#include "context.h"
#include "log.h"

apermon_context *new_context() {
    apermon_context *ctx = (apermon_context *) malloc(sizeof(apermon_context));
    memset(ctx, 0, sizeof(apermon_context));
    ctx->aggr_hash = new_hash(20);
    ctx->trigger_status = new_hash(4);

    return ctx;
}

void free_context(apermon_context *ctx) {
    if (ctx == NULL) {
        return;
    }

    if (ctx->aggr_hash != NULL) {
        free_hash(ctx->aggr_hash, free_aflow);
    }

    if (ctx->trigger_status) {
        free_hash(ctx->trigger_status, free);
    }

    free(ctx);
}

void gc_context(apermon_context *ctx) {
    ctx->last_gc = ctx->now.tv_sec;
    apermon_hash_item *aggr;
    apermon_aggregated_flow *af;

    aggr = ctx->aggr_hash->head;

    while (aggr != NULL) {
        af = (apermon_aggregated_flow *) aggr->value;
        
        if (ctx->now.tv_sec - af->last_modified > CONTEXT_GC_STALE_TIME) {
            aggr = hash_erase(ctx->aggr_hash, aggr, free_aflow);
        } else {
            aggr = aggr->iter_next;
        }
    }
}