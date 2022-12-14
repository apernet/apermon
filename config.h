#ifndef APERMON_CONFIG_H
#define APERMON_CONFIG_H
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include "prefix-list.h"
#include "hash.h"

#define MAX_ENVS 128

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
    uint32_t sample_rate_cap;

    struct _apermon_config_agents *next;
} apermon_config_agents;

typedef struct _apermon_config_ifindexes {
    const apermon_config_agents *agent;
    uint32_t ifindex;

    struct _apermon_config_ifindexes *next;
} apermon_config_ifindexes;

typedef struct _apermon_config_interfaces {
    char *name;
    apermon_config_ifindexes *ifindexes;

    struct _apermon_config_interfaces *next;
} apermon_config_interfaces;

#define APERMON_TRIGGER_CHECK_INGRESS       0b00000001
#define APERMON_TRIGGER_CHECK_EGRESS        0b00000010
#define APERMON_TRIGGER_SET_BAN_TIME        0b00000100
#define APERMON_TRIGGER_SET_BURST_PERIOD    0b00001000

enum aggregator {
    APERMON_AGGREGATOR_HOST,
    APERMON_AGGREGATOR_PREFIX,
    APERMON_AGGREGATOR_NET,
};

typedef struct _apermon_cond_list apermon_cond_list;
typedef struct _apermon_context apermon_context;

typedef struct _apermon_config_prefix_list_elements {
    apermon_prefix *prefix;
    struct _apermon_config_prefix_list_elements *next;
} apermon_config_prefix_list_elements;

typedef struct _apermon_config_prefix_lists {
    char *name;
    apermon_config_prefix_list_elements *elements;

    struct _apermon_config_prefix_lists *next;
} apermon_config_prefix_lists;

typedef struct _apermon_config_prefix_lists_set {
    const apermon_config_prefix_lists *prefix_list;
    struct _apermon_config_prefix_lists_set *next;
} apermon_config_prefix_lists_set;

#define APERMON_SCRIPT_EVENT_BAN    0b00000001
#define APERMON_SCRIPT_EVENT_UNBAN  0b00000010

typedef struct _apermon_config_action_scripts {
    char *name; // script path

    uint8_t flags; /* bit 0: ban, 1: unban */
    char *envs[MAX_ENVS];
    size_t n_envs;

    struct _apermon_config_action_scripts *next;
} apermon_config_action_scripts;

typedef struct _apermon_config_actions {
    char *name;
    apermon_config_action_scripts *scripts;

    struct _apermon_config_actions *next;
} apermon_config_actions;

typedef struct _apermon_config_action_set {
    const apermon_config_actions *action; // not owned by us
    struct _apermon_config_action_set *next;
} apermon_config_action_set;

typedef struct _apermon_config_triggers {
    char *name;

    apermon_config_prefix_lists_set *networks; // owned by us
    uint8_t flags; /* bit 0: ingress check, 1: egress check, 2: ban time override */

    enum aggregator aggregator;

    uint64_t bps;
    uint64_t pps;
    
    uint32_t min_ban_time;
    uint32_t burst_period;

    apermon_cond_list *conds; // owned by us
    apermon_context *ctx; // owned by us

    apermon_config_action_set *actions; // owned by us

    struct _apermon_config_triggers *next;
} apermon_config_triggers;

typedef struct _apermon_config {
    apermon_config_listens *listens;
    apermon_config_agents *agents;
    apermon_config_interfaces *interfaces;
    apermon_config_prefix_lists *prefix_lists;
    apermon_config_actions *actions;
    apermon_config_triggers *triggers;

    apermon_hash *agents_hash; /* maps agent inet/inet6 -> agent struct */

    uint32_t min_ban_time;
    uint32_t burst_period;

    char *status_file;
    uint32_t status_dump_interval;
} apermon_config;

int parse_config(const char *filename, apermon_config **config);
void free_config(apermon_config *config);

#endif // APERMON_CONFIG_H