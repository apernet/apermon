#include <string.h>
#include <stdlib.h>
#include "sflow.h"
#include "prefix-list.h"
#include "log.h"

int apermon_prefix_match_inet(const apermon_prefix_list* lst, uint32_t addr) {
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

int apermon_prefix_match_inet6(const apermon_prefix_list* lst, const uint8_t *addr) {
    // todo

    return 0;
}

apermon_prefix_list *new_prefix() {
    apermon_prefix_list *list = (apermon_prefix_list *) malloc(sizeof(apermon_prefix_list));
    memset(list, 0, sizeof(apermon_prefix_list));

    return list;
}

void free_prefix_list(apermon_prefix_list *list) {
    apermon_prefix_list *ptr = list, *prev = NULL;

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