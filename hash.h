#ifndef APERMON_HASH_H
#define APERMON_HASH_H
#include <stdint.h>
#include <unistd.h>

#if UINTPTR_MAX == 0xFFFFFFFF
    #define hash_ptr_add_or_update hash32_add_or_update
    #define hash_ptr_find hash32_find
    #define hash_ptr_delete hash32_delete
#elif UINTPTR_MAX == 0xFFFFFFFFFFFFFFFFu
    #define hash_ptr_add_or_update hash64_add_or_update
    #define hash_ptr_find hash64_find
    #define hash_ptr_delete hash64_delete
#else
  #error failed to detect pointer size - needed to hash pointers
#endif

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

void hash64_add_or_update(apermon_hash *tbl, const uint8_t *key, void *value, void **old_value);
void *hash64_find(apermon_hash *tbl, const uint8_t *key);
void *hash64_delete(apermon_hash *tbl, const uint8_t *key);

void hash128_add_or_update(apermon_hash *tbl, const uint8_t *key, void *value, void **old_value);
void *hash128_find(apermon_hash *tbl, const uint8_t *key);
void *hash128_delete(apermon_hash *tbl, const uint8_t *key);

apermon_hash_item *hash_erase(apermon_hash *tbl, apermon_hash_item *item, const hash_element_freer_func freer);

apermon_hash *new_hash(uint8_t hash_key_bits);
void free_hash(apermon_hash *hash, const hash_element_freer_func freer);

#endif // APERMON_HASH_H