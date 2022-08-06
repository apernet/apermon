#include <string.h>
#include <stdlib.h>
#include "context.h"

apermon_context *new_context() {
    apermon_context *ctx = (apermon_context *) malloc(sizeof(apermon_context));
    memset(ctx, 0, sizeof(apermon_context));
    ctx->aggr_hash = new_hash();

    return ctx;
}

void free_context(apermon_context *ctx) {
    if (ctx == NULL) {
        return;
    }

    if (ctx->aggr_hash != NULL) {
        free_hash(ctx->aggr_hash);
    }

    free(ctx);
}