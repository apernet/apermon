#ifndef APERMON_PREFIX_LSIT_H
#define APERMON_PREFIX_LSIT_H
#include <stdint.h>

typedef struct _apermon_config_prefix_list_elements apermon_config_prefix_list_elements;

typedef struct _apermon_prefix {
    uint32_t af; /* enum sflow_af */
    union {
        uint32_t inet;
        uint8_t inet6[16];
    };
    
    union {
        uint32_t mask;
        uint8_t mask6[16];
    };

    uint8_t cidr;
} apermon_prefix;

int apermon_prefix_match_inet(const apermon_prefix* lst, uint32_t addr);
int apermon_prefix_match_inet6(const apermon_prefix* lst, const uint8_t *addr);

int apermon_prefix_list_match_inet(const apermon_config_prefix_list_elements* lst, uint32_t addr);
int apermon_prefix_list_match_inet6(const apermon_config_prefix_list_elements* lst, const uint8_t *addr);

apermon_prefix *new_prefix();
void free_prefix(apermon_prefix *prefix);

#endif // APERMON_PREFIX_LSIT_H