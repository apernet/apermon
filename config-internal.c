#include <stdlib.h>
#include <string.h>
#include "config-internal.h"
#include "log.h"

static struct addrinfo _gai_hints;
static int _retval = 0;

static apermon_config *_config;

static apermon_config_listens *_current_listen;
static apermon_config_agents *_current_agent;
static apermon_interfaces *_current_interface;
static apermon_config_triggers *_current_trigger;

#define GET_CURRENT_NAMED_STRUCT_FUNC(type, funcname, current_var) type *funcname() {\
    if ((current_var) == NULL) {\
        (current_var) = (type *) malloc(sizeof(type));\
        memset((current_var), 0, sizeof(type));\
    }\
    return (current_var);\
}

#define END_NAMED_STRUCT_FUNC(type, funcname, current_var, field) type *funcname(const char *name) {\
    if ((current_var) == NULL) { return NULL; }\
    (current_var)->name = strdup(name);\
    type *i = _config->field, *prev = NULL;\
    while (i != NULL) { prev = i; i = i->next; }\
    if (prev == NULL) { _config->field = (current_var); }\
    else { prev->next = (current_var); }\
    type *ret = current_var;\
    current_var = NULL;\
    return ret;\
}

#define NEW_LIST_ELEMENT_FUNC(type, funcname, parent_type, parent_var, field) type *funcname() {\
    parent_type *parent = (parent_var);\
    type *new_element = (type *) malloc(sizeof(type));\
    type *i = parent->field, *prev = NULL;\
    while (i != NULL) { prev = i; i = i->next; }\
    if (prev == NULL) { parent->field = new_element; }\
    else { prev->next = new_element; };\
    new_element->next = NULL;\
    return new_element;\
}

void start_config() {
    _config = (apermon_config *) malloc(sizeof(apermon_config));
    _current_listen = _config->listens = NULL;
    _current_agent = _config->agents = NULL;
    _current_interface = _config->interfaces = NULL;
    _current_trigger = _config->triggers = NULL;

    memset(&_gai_hints, 0, sizeof(struct addrinfo));
    _gai_hints.ai_family = AF_UNSPEC;
    _gai_hints.ai_socktype = SOCK_DGRAM;
    _gai_hints.ai_flags = AI_PASSIVE;
    _gai_hints.ai_protocol = IPPROTO_UDP;
    _gai_hints.ai_canonname = NULL;
    _gai_hints.ai_addr = NULL;
    _gai_hints.ai_next = NULL;
}

void end_config() {
    if (_current_agent != NULL) {
        free(_current_agent);
    }
}

void store_retval(int retval) {
    _retval = retval;
}

int get_retval() {
    return _retval;
}

apermon_config *get_config() {
    return _config;
}

static NEW_LIST_ELEMENT_FUNC(apermon_config_listens, new_listen_internal, apermon_config, _config, listens);

apermon_config_listens *new_listen() {
    return _current_listen = new_listen_internal();
}

apermon_config_listens *end_listen(const char *host, uint16_t port) {
    char port_str[6];
    memset(port_str, 0, sizeof(port_str));
    sprintf(port_str, "%u", port);

    int ret = getaddrinfo(host, port_str, &_gai_hints, &_current_listen->addr);

    if (ret != 0) {
        log_fatal("getaddrinfo() on \"%s\" failed: %s\n", host, gai_strerror(ret));
        return NULL;
    }

    return _current_listen;
}

GET_CURRENT_NAMED_STRUCT_FUNC(apermon_config_agents, get_current_agent, _current_agent);

END_NAMED_STRUCT_FUNC(apermon_config_agents, end_agent, _current_agent, agents);

NEW_LIST_ELEMENT_FUNC(apermon_config_agent_addresses, new_address, apermon_config_agents, get_current_agent(), addresses);

apermon_config_agent_addresses *add_agent_address_inet(const struct in_addr *addr) {
    apermon_config_agent_addresses *a = new_address();
    a->af = AF_INET;
    memcpy(&a->inet, addr, sizeof(a->inet));

    return a;
}

apermon_config_agent_addresses *add_agent_address_inet6(const struct in6_addr *addr) {
    apermon_config_agent_addresses *a = new_address();
    a->af = AF_INET6;
    memcpy(&a->inet6, addr, sizeof(a->inet6));

    return a;
}

GET_CURRENT_NAMED_STRUCT_FUNC(apermon_interfaces, get_current_interface, _current_interface);

END_NAMED_STRUCT_FUNC(apermon_interfaces, end_interface, _current_interface, interfaces);

NEW_LIST_ELEMENT_FUNC(apermon_ifindexes, new_ifindex, apermon_interfaces, get_current_interface(), ifindexes);

apermon_ifindexes *add_ifindex(const char *agent, uint32_t ifindex) {
    apermon_ifindexes *i = new_ifindex();
    i->agent = strdup(agent);
    i->ifindex = ifindex;

    return i;
}
