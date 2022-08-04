#include <stdlib.h>
#include "config.h"

void free_config(apermon_config *config) {
    apermon_config_listens *l = config->listens, *prev_l = NULL;
    apermon_config_agents *a = config->agents, *prev_a = NULL;
    apermon_config_agent_addresses *addr = NULL, *prev_addr = NULL;
    
    while (l != NULL) {
        if (prev_l != NULL) {
            free(prev_l);
        }

        if (l->addr != NULL) {
            freeaddrinfo(l->addr);
        }

        prev_l = l;
        l = l->next;
    }

    if (prev_l != NULL) {
        free(prev_l);
    }

    while (a != NULL) {
        if (prev_a != NULL) {
            free(prev_a);
        }

        if (a->name != NULL) {
            free(a->name);
        }

        addr = a->addresses, prev_addr = NULL;

        while (addr != NULL) {
            if (prev_addr != NULL) {
                free(prev_addr);
            }

            prev_addr = addr;
            addr = addr->next;
        }

        if (prev_addr != NULL) {
            free(prev_addr);
        }

        prev_a = a;
        a = a->next;
    }

    if (prev_a != NULL) {
        free(prev_a);
    }

    free(config);
}