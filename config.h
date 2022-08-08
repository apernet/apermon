#ifndef APERMON_CONFIG_H
#define APERMON_CONFIG_H
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include "prefix-list.h"

enum listen_protocol {
    APERMON_LISTEN_SFLOW_V5,
};

typedef struct _apermon_config_listens {
    struct addrinfo *addr;
    enum listen_protocol proto;
    struct _apermon_config_listens *next;
} apermon_config_listens;

typedef struct _apermon_config_agent_addresses {
    int af; /* AF_INET | AF_INET6 */ 
    union {
        struct in_addr inet;
        struct in6_addr inet6;
    };

    struct _apermon_config_agent_addresses *next;
} apermon_config_agent_addresses;

typedef struct _apermon_config_agents {
    char *name;
    apermon_config_agent_addresses *addresses;

    struct _apermon_config_agents *next;
} apermon_config_agents;

#define APERMON_TRIGGER_CHECK_INGRESS   0b00000001
#define APERMON_TRIGGER_CHECK_EGRESS    0b00000010
#define APERMON_TRIGGER_SET_BAN_TIME    0b00000100

enum aggregator {
    APERMON_AGGREGATOR_HOST,
    APERMON_AGGREGATOR_NET,
};

typedef struct _apermon_cond_list apermon_cond_list;
typedef struct _apermon_context apermon_context;

typedef struct _apermon_config_prefix_list_element {
    apermon_prefix *prefix;
    struct _apermon_config_prefix_list_element *next;
} apermon_config_prefix_list_element;

typedef struct _apermon_config_prefix_list {
    char *name;
    apermon_config_prefix_list_element *elements;

    struct _apermon_config_prefix_list *next;
} apermon_config_prefix_list;

typedef struct _apermon_prefix_list_set {
    char *candidate;
    const apermon_config_prefix_list *prefix_list;
    struct _apermon_prefix_list_set *next;
} apermon_prefix_list_set;

typedef struct _apermon_config_triggers {
    char *name;

    apermon_prefix_list_set *prefixes; // owned by us
    uint8_t flags; /* bit 0: ingress check, 1: egress check, 2: ban time override */

    enum aggregator aggregator;

    uint64_t bps;
    uint64_t pps;
    
    uint32_t min_ban_time;

    apermon_cond_list *conds; // owned by us
    apermon_context *ctx; // owned by us

    // todo: action

    struct _apermon_config_triggers *next;
} apermon_config_triggers;

typedef struct _apermon_config_ifindexes {
    char *agent;
    uint32_t ifindex;

    struct _apermon_config_ifindexes *next;
} apermon_config_ifindexes;

typedef struct _apermon_config_interfaces {
    char *name;
    apermon_config_ifindexes *ifindexes;

    struct _apermon_config_interfaces *next;
} apermon_config_interfaces;

typedef struct _apermon_config {
    apermon_config_listens *listens;
    apermon_config_agents *agents;
    apermon_config_interfaces *interfaces;
    apermon_config_prefix_list *prefix_lists;

    apermon_config_triggers *triggers;

    uint32_t min_ban_time;
} apermon_config;

int parse_config(const char *filename, apermon_config **config);
void free_config(apermon_config *config);

#endif // APERMON_CONFIG_H