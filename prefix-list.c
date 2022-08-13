#include <string.h>
#include <stdlib.h>
#include "sflow.h"
#include "config.h"
#include "prefix-list.h"
#include "log.h"

void apermon_inet6_mask_apply(uint8_t *masked, const uint8_t* from, const uint8_t *mask) {
    uint8_t i;

    for (i = 0; i < 16; ++i) {
        masked[i] = from[i] & mask[i];
    }
}

int apermon_prefix_match_inet(const apermon_prefix* pfx, uint32_t addr) {
    return (addr & pfx->mask) == pfx->inet;
}

int apermon_prefix_match_inet6(const apermon_prefix* lst, const uint8_t *addr) {
    uint8_t masked[16];

    apermon_inet6_mask_apply(masked, addr, lst->mask6);

    return memcmp(masked, lst->inet6, sizeof(masked)) == 0;
}

const apermon_prefix* apermon_prefix_list_match_inet(const apermon_config_prefix_list_elements* lst, uint32_t addr) {
    const apermon_prefix *pfx;

    while (lst != NULL) {
        pfx = lst->prefix;
        if (pfx->af != SFLOW_AF_INET) {
            lst = lst->next;
            continue;
        }

        if (apermon_prefix_match_inet(pfx, addr)) {
            return pfx;
        }

        lst = lst->next;
    }

    return NULL;
}

const apermon_prefix* apermon_prefix_list_match_inet6(const apermon_config_prefix_list_elements* lst, const uint8_t *addr) {
    const apermon_prefix *pfx;

    while (lst != NULL) {
        pfx = lst->prefix;
        if (pfx->af != SFLOW_AF_INET6) {
            lst = lst->next;
            continue;
        }

        if (apermon_prefix_match_inet6(pfx, addr)) {
            return pfx;
        }

        lst = lst->next;
    }

    return NULL;
}

apermon_prefix *new_prefix() {
    apermon_prefix *pfx = (apermon_prefix *) malloc(sizeof(apermon_prefix));
    memset(pfx, 0, sizeof(apermon_prefix));
    
    return pfx;
}

void free_prefix(apermon_prefix *prefix) {
    free(prefix);
}