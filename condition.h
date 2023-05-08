#ifndef APERMON_CONDITION_H
#define APERMON_CONDITION_H
#include "extract.h"
#include "context.h"

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
} apermon_cond_list;

/* cond functions */

int cond_list(const apermon_flow_record* record, const void* arg /* apermon_cond_list* */); /* eval cond-list */
int cond_in_interface(const apermon_flow_record* record, const void* arg /* apermon_config_interfaces** */); /* keep only flows matching given in interface */
int cond_out_interface(const apermon_flow_record* record, const void* arg /* apermon_config_interfaces** */); /* keep only flows matching given out interface */
int cond_src(const apermon_flow_record* record, const void* arg /* apermon_config_prefix_list_elements** */); /* keep only flow where dst in list */
int cond_dst(const apermon_flow_record* record, const void* arg /* apermon_config_prefix_list_elements** */); /* keep only flow where src in list */
int cond_proto(const apermon_flow_record* record, const void* arg /* uint8_t* */); /* keep only flow where l3proto in list */
int cond_src_port(const apermon_flow_record* record, const void* arg /* uint16_t* */); /* keep only flow where src port in list */
int cond_dst_port(const apermon_flow_record* record, const void* arg /* uint16_t* */); /* keep only flow where dst port in list */
int cond_is_fragment(const apermon_flow_record* record, const void* arg /* unused */); /* keep only fragment */

/* misc functions */

void cond_begin(apermon_context *ctx);
void select_flow(const apermon_flow_record *flow);

#endif // APERMON_CONDITION_H