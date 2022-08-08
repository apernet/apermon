#include <stdlib.h>
#include "config.h"

void free_config(apermon_config *config) {
    apermon_config_listens *l = config->listens, *prev_l = NULL;
    apermon_config_agents *a = config->agents, *prev_a = NULL;
    apermon_config_agent_addresses *addr = NULL, *prev_addr = NULL;
    apermon_config_interfaces *i = config->interfaces, *prev_i = NULL; 
    apermon_config_ifindexes *ifindex = NULL, *prev_ifindex = NULL;
    
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

    while (i != NULL) {
        if (prev_i != NULL) {
            free(prev_i);
        }

        if (i->name != NULL) {
            free(i->name);
        }

        ifindex = i->ifindexes, prev_ifindex = NULL;
        while (ifindex != NULL) {
            if (prev_ifindex != NULL) {
                free(prev_ifindex);
            }

            if (ifindex->agent != NULL) {
                free(ifindex->agent);
            }

            prev_ifindex = ifindex;
            ifindex = ifindex->next;
        }

        if (prev_ifindex != NULL) {
            free(prev_ifindex);
        }

        prev_i = i;
        i = i->next;
    }

    if (prev_i != NULL) {
        free(prev_i);
    }

    free(config);
}

/*
void free_prefix_list(apermon_prefix *list) {
    apermon_prefix *ptr = list, *prev = NULL;

    while (ptr != NULL) {
        if (prev != NULL) {
            free(prev);
        }

        prev = ptr;
        ptr = ptr->next;
    }

    if (prev != NULL) {
        free(prev);
    }
}*/