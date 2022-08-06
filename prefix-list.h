#ifndef APERMON_PREFIX_LSIT_H
#define APERMON_PREFIX_LSIT_H
#include <stdint.h>

typedef struct _apermon_prefix_list {
    uint32_t af; /* enum sflow_af */
    union {
        uint32_t inet;
        uint8_t inet6[16];
    };
    
    union {
        uint32_t mask;
        uint8_t mask6[16];
    };

    struct _apermon_prefix_list *next;
} apermon_prefix_list;

int apermon_prefix_match_inet(const apermon_prefix_list* lst, uint32_t addr);
int apermon_prefix_match_inet6(const apermon_prefix_list* lst, const uint8_t *addr);

apermon_prefix_list *new_prefix();
void free_prefix_list(apermon_prefix_list *list);

#endif // APERMON_PREFIX_LSIT_H