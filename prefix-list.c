#include <string.h>
#include <stdlib.h>
#include "sflow.h"
#include "prefix-list.h"
#include "log.h"

int apermon_prefix_match_inet(const apermon_prefix_lists* lst, uint32_t addr) {
    while (lst != NULL) {
        if (lst->af != SFLOW_AF_INET) {
            lst = lst->next;
            continue;
        }

        if ((addr & lst->mask) == lst->inet) {
            return 1;
        }

        lst = lst->next;
    }

    return 0;
}

int apermon_prefix_match_inet6(const apermon_prefix_lists* lst, const uint8_t *addr) {
    // todo

    return 0;
}

apermon_prefix_lists *new_prefix() {
    apermon_prefix_lists *list = (apermon_prefix_lists *) malloc(sizeof(apermon_prefix_lists));
    memset(list, 0, sizeof(apermon_prefix_lists));

    return list;
}

void free_prefix_list(apermon_prefix_lists *list) {
    apermon_prefix_lists *ptr = list, *prev = NULL;

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
}