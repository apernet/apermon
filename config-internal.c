#include <stdlib.h>
#include <string.h>
#include "config-internal.h"
#include "log.h"

static struct addrinfo _gai_hints;
static int _retval = 0;

static apermon_config *_config;

static apermon_config_listens *_current_listen;
static apermon_config_agents *_current_agent;

void start_config() {
    _config = (apermon_config *) malloc(sizeof(apermon_config));
    _current_listen = _config->listens = NULL;
    _current_agent = _config->agents = NULL;

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

apermon_config_listens *new_listen() {
    apermon_config_listens *l = _config->listens, *prev = NULL;
    while (l != NULL) {
        prev = l;
        l = l->next;
    }

    if (prev == NULL) {
        _current_listen = _config->listens = (apermon_config_listens *) malloc(sizeof(apermon_config_listens));
    } else {
        _current_listen = prev->next = (apermon_config_listens *) malloc(sizeof(apermon_config_listens));
    }

    _current_listen->next = NULL;

    return _current_listen;
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

apermon_config_agents *get_current_agent() {
    if (_current_agent == NULL) {
        _current_agent = (apermon_config_agents *) malloc(sizeof(apermon_config_agents));
        memset(_current_agent, 0, sizeof(apermon_config_agents));
    }

    return _current_agent;
}

apermon_config_agents *end_agent(const char *agent_name) {

    if (_current_agent == NULL) {
        return NULL;
    }

    _current_agent->name = strdup(agent_name);

    apermon_config_agents *a = _config->agents, *prev = NULL;
    while (a != NULL) {
        prev = a;
        a = a->next;
    }

    if (prev == NULL) {
        _config->agents = _current_agent;
    } else {
        prev->next = _current_agent;
    }

    apermon_config_agents *ret = _current_agent;
    _current_agent = NULL;

    return ret;
}

apermon_config_agent_addresses *new_address() {
    apermon_config_agents *agent = get_current_agent();
    apermon_config_agent_addresses *new_addr = (apermon_config_agent_addresses *) malloc(sizeof(apermon_config_agent_addresses));

    apermon_config_agent_addresses *a = agent->addresses, *prev = NULL;
    while (a != NULL) {
        prev = a;
        a = a->next;
    }

    if (prev == NULL) {
        agent->addresses = new_addr;
    } else {
        prev->next = new_addr;
    }

    new_addr->next = NULL;

    return new_addr;
}

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