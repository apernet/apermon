#ifndef APERMON_CONFIG_H
#define APERMON_CONFIG_H
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include "apermon.h"

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

typedef struct _apermon_config_triggers {
    apermon_prefix_list *prefixes;
    uint8_t flags; /* bit 0: ingress check, 1: egress check, 2: ban time override */
    
    uint32_t min_ban_time;
    struct _apermon_config_triggers *next;
} apermon_config_triggers;

typedef struct _apermon_ifindexes {
    char *agent;
    uint32_t ifindex;

    struct _apermon_ifindexes *next;
} apermon_ifindexes;

typedef struct _apermon_interfaces {
    char *name;
    apermon_ifindexes *ifindexes;

    struct _apermon_interfaces *next;
} apermon_interfaces;

typedef struct _apermon_config {
    apermon_config_listens *listens;
    apermon_config_agents *agents;
    apermon_interfaces *interfaces;

    apermon_config_triggers *triggers;

    uint32_t min_ban_time;
} apermon_config;

int parse_config(const char *filename, apermon_config **config);
void free_config(apermon_config *config);

#endif // APERMON_CONFIG_H