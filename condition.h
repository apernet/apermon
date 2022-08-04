#ifndef APERMON_CONDITION_H
#define APERMON_CONDITION_H
#include "extract.h"
#include "context.h"

typedef struct _apermon_cond_selected_flows {
    const apermon_flow_record *flow;
    struct _apermon_cond_selected_flows *next;
} apermon_cond_selected_flows;

typedef int (*apermon_cond_func_t)(apermon_context *ctx, const apermon_flow_record* record, const void* arg);

typedef struct _apermon_cond_func_list {
    apermon_cond_func_t func;

    struct _apermon_cond_func_list *next;
} apermon_cond_func_list;

enum cond_type {
    AND,
    OR,
    NOT,
};

typedef struct _apermon_cond_list {
    enum cond_type type;
    const apermon_cond_func_list *funcs;

    struct _apermon_cond_list *next;
} apermon_cond_list;

/* cond functions */

int cond_list(apermon_context *ctx, const apermon_flow_record* record, const void* arg /* apermon_cond_list* */); /* eval cond-list */
int cond_interface(apermon_context *ctx, const apermon_flow_record* record, const void* arg /* apermon_interface* */); /* keep only flows matching given interface */
int cond_bps(apermon_context *ctx, const apermon_flow_record* record, const void* arg /* uint64_t* */); /* keep only flow > given bps */
int cond_pps(apermon_context *ctx, const apermon_flow_record* record, const void* arg /* uint64_t* */); /* keep only flow > given pps */
int cond_src(apermon_context *ctx, const apermon_flow_record* record, const void* arg /* apermon_pfx_list* */); /* keep only flow where dst in list */
int cond_dst(apermon_context *ctx, const apermon_flow_record* record, const void* arg /* apermon_pfx_list* */); /* keep only flow where src in list */
int cond_proto(apermon_context *ctx, const apermon_flow_record* record, const void* arg /* apermon_uint_set* */); /* keep only flow where l3proto in list */
int cond_src_port(apermon_context *ctx, const apermon_flow_record* record, const void* arg /* apermon_uint_set* */); /* keep only flow where src port in list */
int cond_dst_port(apermon_context *ctx, const apermon_flow_record* record, const void* arg /* apermon_uint_set* */); /* keep only flow where dst port in list */

#endif // APERMON_CONDITION_H