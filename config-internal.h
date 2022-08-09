#ifndef APERNET_CONFIG_INTERNAL_H
#define APERNET_CONFIG_INTERNAL_H
#include <arpa/inet.h>
#include "config.h"
#include "prefix-list.h"
#include "condition.h"

#define FILTER_RULES_MAX_NESTING 64

void start_config();
void end_config();

void store_retval(int retval);
int get_retval();

apermon_config *get_config();

apermon_config_listens *listen_fill_gai(apermon_config_listens *listen, const char *host, uint16_t port);
apermon_config_prefix_list_elements *new_prefix_inet(const struct in_addr *addr, uint8_t prefix_len);
apermon_config_prefix_list_elements *new_prefix_inet6(const struct in6_addr *addr, uint8_t prefix_len);
apermon_cond_func_list *new_cond_func_list_element(apermon_cond_func func, void *arg);

apermon_config_agents *get_current_agent();
apermon_config_agents *end_agent(const char *agent_name);

apermon_config_interfaces *get_current_interface();
apermon_config_interfaces *end_interface(const char *ifname);

apermon_config_prefix_lists *get_current_prefix_list();
apermon_config_prefix_lists *end_prefix_list(const char *name);

apermon_config_actions *get_current_action();
apermon_config_actions *end_action(const char *name);

apermon_config_action_scripts *get_current_action_script();
apermon_config_action_scripts *end_action_script(const char *name);

apermon_config_triggers *get_current_trigger();
apermon_config_triggers *end_trigger(const char *name);

apermon_config_agents *get_agent(const char *name);
apermon_config_interfaces *get_interface(const char *name);
apermon_config_prefix_lists *get_prefix_list(const char *name);
apermon_config_actions *get_action(const char *name);

#endif // APERNET_CONFIG_INTERNAL_H