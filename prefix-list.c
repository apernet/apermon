#include "sflow.h"
#include "prefix-list.h"

int apermon_prefix_match_inet(const apermon_prefix_list* lst, uint32_t addr) {
    while (lst != NULL) {
        if (lst->af != SFLOW_AF_INET) {
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