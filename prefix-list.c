#include <string.h>
#include <stdlib.h>
#include "sflow.h"
#include "config.h"
#include "prefix-list.h"
#include "log.h"

int apermon_prefix_match_inet(const apermon_prefix* pfx, uint32_t addr) {
    return (addr & pfx->mask) == pfx->inet;
}

int apermon_prefix_match_inet6(const apermon_prefix* lst, const uint8_t *addr) {
    // todo

    return 0;
}

int apermon_prefix_list_match_inet(const apermon_config_prefix_list_elements* lst, uint32_t addr) {
    const apermon_prefix *pfx;

    while (lst != NULL) {
        pfx = lst->prefix;
        if (pfx->af != SFLOW_AF_INET) {
            lst = lst->next;
            continue;
        }

        if (apermon_prefix_match_inet(pfx, addr)) {
            return 1;
        }

        lst = lst->next;
    }

    return 0;
}

int apermon_prefix_list_match_inet6(const apermon_config_prefix_list_elements* lst, const uint8_t *addr) {
    const apermon_prefix *pfx;

    while (lst != NULL) {
        pfx = lst->prefix;
        if (pfx->af != SFLOW_AF_INET) {
            lst = lst->next;
            continue;
        }

        if (apermon_prefix_match_inet6(pfx, addr)) {
            return 1;
        }

        lst = lst->next;
    }

    return 0;
}

apermon_prefix *new_prefix() {
    apermon_prefix *pfx = (apermon_prefix *) malloc(sizeof(apermon_prefix));
    memset(pfx, 0, sizeof(apermon_prefix));
    
    return pfx;
}

void free_prefix(apermon_prefix *prefix) {
    free(prefix);
}