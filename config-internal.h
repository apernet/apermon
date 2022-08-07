#ifndef APERNET_CONFIG_INTERNAL_H
#define APERNET_CONFIG_INTERNAL_H
#include <arpa/inet.h>
#include "config.h"
#include "prefix-list.h"

void start_config();
void end_config();

void store_retval(int retval);
int get_retval();

apermon_config *get_config();

apermon_config_listens *new_listen();
apermon_config_listens *end_listen(const char *host, uint16_t port);

apermon_config_agents *get_current_agent();
apermon_config_agents *end_agent(const char *agent_name);

apermon_config_agent_addresses *new_address();
apermon_config_agent_addresses *add_agent_address_inet(const struct in_addr *addr);
apermon_config_agent_addresses *add_agent_address_inet6(const struct in6_addr *addr);

apermon_config_interfaces *get_current_interface();
apermon_config_interfaces *end_interface(const char *ifname);

apermon_config_ifindexes *new_ifindex();
apermon_config_ifindexes *add_ifindex(const char *agent, uint32_t ifindex);

apermon_prefix_lists *end_prefix_list(const char *name);
apermon_prefix_lists *add_prefix_inet(const struct in_addr *addr, uint8_t prefix_len);
apermon_prefix_lists *add_prefix_inet6(const struct in6_addr *addr, uint8_t prefix_len);

#endif // APERNET_CONFIG_INTERNAL_H