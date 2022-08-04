#ifndef APERMON_HASH_H
#define APERMON_HASH_H
#include <stdint.h>
#include <unistd.h>
#define HASH_SIZE 20
#define HASH_MASK ((1 << HASH_SIZE) - 1)

typedef struct _apermon_hash_item {
    size_t key_len;
    uint8_t *key; /* ownership: apermon_hash */
    void *value; /* ownership: caller */

    struct _apermon_hash_item *next;
} apermon_hash_item;

typedef struct _apermon_hash {
    apermon_hash_item *items[HASH_MASK]; /* ownership: apermon_hash */
} apermon_hash;

apermon_hash_item *hash32_add_or_update(apermon_hash *tbl, const uint32_t *key, void *value, void **old_value);
apermon_hash_item *hash32_find(apermon_hash *tbl, const uint32_t *key);

apermon_hash_item *hash128_add_or_update(apermon_hash *tbl, const uint8_t *key, void *value, void **old_value);
apermon_hash_item *hash128_find(apermon_hash *tbl, const uint8_t *key);

apermon_hash *new_hash();
void free_hash(apermon_hash *hash);

#endif // APERMON_HASH_H