#ifndef APERMON_HASH_H
#define APERMON_HASH_H
#include <stdint.h>
#include <unistd.h>

typedef struct _apermon_hash_item {
    size_t key_len;
    uint32_t hashed_key;
    uint8_t *key; /* ownership: apermon_hash */
    void *value; /* ownership: caller */

    struct _apermon_hash_item *next;
    struct _apermon_hash_item *prev;
    
    struct _apermon_hash_item *iter_next;
    struct _apermon_hash_item *iter_prev;
} apermon_hash_item;

typedef struct _apermon_hash {
    apermon_hash_item *head;
    apermon_hash_item *tail;

    uint8_t hash_key_bits;
    uint32_t hash_mask;
    apermon_hash_item **items; /* ownership: apermon_hash */
} apermon_hash;

typedef void (*hash_element_freer_func)(void *value);

void hash32_add_or_update(apermon_hash *tbl, const uint32_t *key, void *value, void **old_value);
void *hash32_find(apermon_hash *tbl, const uint32_t *key);
void *hash32_delete(apermon_hash *tbl, const uint32_t *key);

void hash128_add_or_update(apermon_hash *tbl, const uint8_t *key, void *value, void **old_value);
void *hash128_find(apermon_hash *tbl, const uint8_t *key);
void *hash128_delete(apermon_hash *tbl, const uint8_t *key);

apermon_hash_item *hash_erase(apermon_hash *tbl, apermon_hash_item *item, const hash_element_freer_func freer);

apermon_hash *new_hash(uint8_t hash_key_bits);
void free_hash(apermon_hash *hash, const hash_element_freer_func freer);

#endif // APERMON_HASH_H