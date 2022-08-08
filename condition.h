#ifndef APERMON_CONDITION_H
#define APERMON_CONDITION_H
#include "extract.h"
#include "context.h"

typedef struct _apermon_cond_selected_flows {
    const apermon_flow_record *flow;
    struct _apermon_cond_selected_flows *next;
} apermon_cond_selected_flows;

typedef int (*apermon_cond_func)(const apermon_flow_record* record, const void* arg);

typedef struct _apermon_cond_func_list {
    apermon_cond_func func;
    void *arg;

    struct _apermon_cond_func_list *next;
} apermon_cond_func_list;

enum cond_type {
    APERMON_COND_AND,
    APERMON_COND_OR,
    APERMON_COND_NOT,
};

typedef struct _apermon_cond_list {
    enum cond_type type;
    apermon_cond_func_list *funcs;

    struct _apermon_cond_list *next;
} apermon_cond_list;

/* cond functions */

int cond_list(const apermon_flow_record* record, const void* arg /* apermon_cond_list* */); /* eval cond-list */
int cond_interface(const apermon_flow_record* record, const void* arg /* apermon_interface* */); /* keep only flows matching given interface */
int cond_src(const apermon_flow_record* record, const void* arg /* apermon_config_prefix_list_elements* */); /* keep only flow where dst in list */
int cond_dst(const apermon_flow_record* record, const void* arg /* apermon_config_prefix_list_elements* */); /* keep only flow where src in list */
int cond_proto(const apermon_flow_record* record, const void* arg /* uint8_t* */); /* keep only flow where l3proto in list */
int cond_src_port(const apermon_flow_record* record, const void* arg /* uint16_t* */); /* keep only flow where src port in list */
int cond_dst_port(const apermon_flow_record* record, const void* arg /* uint16_t* */); /* keep only flow where dst port in list */

/* misc functions */

void select_flow(apermon_context *ctx, const apermon_flow_record *flow);
void free_selected_flows(apermon_context *ctx);

#endif // APERMON_CONDITION_H