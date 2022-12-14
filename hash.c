#include <string.h>
#include <stdlib.h>
#include "hash.h"

static inline uint32_t hash32(apermon_hash *hash, const uint32_t *buf) {
    return __builtin_ia32_crc32si(0, *buf) & hash->hash_mask;
}

static inline uint32_t hash64(apermon_hash *hash, const uint8_t *buf) {
    uint32_t res = 0, i;

    for (i = 0; i < sizeof(uint64_t) / sizeof(uint32_t); ++i, buf += sizeof(uint32_t)) {
        res = __builtin_ia32_crc32si(res, * (uint32_t *) buf);
    }

    return res & hash->hash_mask;
}

static inline uint32_t hash128(apermon_hash *hash, const uint8_t *buf) {
    uint32_t res = 0, i;

    // 16: len of bin inet6 addr
    for (i = 0; i < 16 / sizeof(uint32_t); ++i, buf += sizeof(uint32_t)) {
        res = __builtin_ia32_crc32si(res, * (uint32_t *) buf);
    }

    return res & hash->hash_mask;
}

static inline apermon_hash_item *_hash_find(apermon_hash *tbl, uint32_t hashed_key, const uint8_t *key, size_t key_len, apermon_hash_item **last) {
    apermon_hash_item *item = tbl->items[hashed_key], *target = NULL, *prev = NULL;

    while (item != NULL) {
        if (item->key_len != key_len) {
            item = item->next;
            continue;
        }

        if (memcmp(item->key, key, key_len) == 0) {
            target = item;
            break;
        }

        prev = item;
        item = item->next;
    }

    if (last != NULL) {
        *last = prev;
    }

    return target;
}

static inline void *_hash_delete(apermon_hash *tbl, uint32_t hashed_key, const uint8_t *key, size_t key_len) {
    apermon_hash_item *item = _hash_find(tbl, hashed_key, key, key_len, NULL);

    void *val = item->value;

    hash_erase(tbl, item, NULL);

    return val;
}

static inline void _hash_add_or_update(apermon_hash *tbl, uint32_t hashed_key, const uint8_t *key, size_t key_len, void *value, void **old_value) {
    apermon_hash_item *target, *prev = NULL;

    target = _hash_find(tbl, hashed_key, key, key_len, &prev);

    if (target != NULL) {
        *old_value = target->value;
        target->value = value;
        return;
    }

    apermon_hash_item *item = (apermon_hash_item *) malloc(sizeof(apermon_hash_item));

    item->key_len = key_len;
    item->key = malloc(key_len);
    item->hashed_key = hashed_key;
    memset(item->key, 0, key_len);
    memcpy(item->key, key, key_len);
    item->value = value;
    item->next = NULL;

    item->iter_next = NULL;
    item->iter_prev = tbl->tail;

    if (tbl->head == NULL) {
        tbl->head = tbl->tail = item;
    } else {
        tbl->tail->iter_next = item;
        tbl->tail = item;
    }

    item->prev = prev;

    if (prev == NULL) {
        tbl->items[hashed_key] = item;
    } else {
        prev->next = item;
    }
}

void hash32_add_or_update(apermon_hash *tbl, const void *key, void *value, void **old_value) {
    return _hash_add_or_update(tbl, hash32(tbl, key), key, sizeof(uint32_t), value, old_value);
}

void hash64_add_or_update(apermon_hash *tbl, const void *key, void *value, void **old_value) {
    return _hash_add_or_update(tbl, hash64(tbl, key), key, sizeof(uint64_t), value, old_value);
}

void hash128_add_or_update(apermon_hash *tbl, const void *key, void *value, void **old_value) {
    return _hash_add_or_update(tbl, hash128(tbl, key), key, 16 * sizeof(uint8_t), value, old_value);
}

void *hash32_find(apermon_hash *tbl, const void *key) {
    apermon_hash_item *item = _hash_find(tbl, hash32(tbl, key), key, sizeof(uint32_t), NULL);

    return item == NULL ? NULL : item->value;
}

void *hash64_find(apermon_hash *tbl, const void *key) {
    apermon_hash_item *item = _hash_find(tbl, hash64(tbl, key), key, sizeof(uint64_t), NULL);

    return item == NULL ? NULL : item->value;
}

void *hash128_find(apermon_hash *tbl, const void *key) {
    apermon_hash_item *item = _hash_find(tbl, hash128(tbl, key), key, 16 * sizeof(uint8_t), NULL);

    return item == NULL ? NULL : item->value;
}

void *hash32_delete(apermon_hash *tbl, const void *key) {
    return _hash_delete(tbl, hash32(tbl, key), key, sizeof(uint32_t));
}

void *hash64_delete(apermon_hash *tbl, const void *key) {
    return _hash_delete(tbl, hash64(tbl, key), key, sizeof(uint64_t));
}

void *hash128_delete(apermon_hash *tbl, const void *key) {
    return _hash_delete(tbl, hash128(tbl, key), key, 16 * sizeof(uint8_t));
}

apermon_hash_item *hash_erase(apermon_hash *tbl, apermon_hash_item *item, const hash_element_freer_func freer) {
    apermon_hash_item *inext = item->iter_next, *iprev = item->iter_prev;
    apermon_hash_item *next = item->next, *prev = item->prev;

    if (inext) {
        inext->iter_prev = iprev;
    }

    if (next) {
        next->prev = prev;
    }

    if (iprev) {
        iprev->iter_next = inext;
    }

    if (prev) {
        prev->next = next;
    }
    
    if (tbl->head == item) {
        tbl->head = inext;
    }

    if (tbl->tail == item) {
        tbl->tail = iprev;
    } 

    if (tbl->items[item->hashed_key] == item) {
        tbl->items[item->hashed_key] = next;
    }

    if (freer) {
        freer(item->value);
    }

    free(item->key);
    free(item);

    return inext;
}

apermon_hash *new_hash(uint8_t hash_key_bits) {
    apermon_hash *h = (apermon_hash *) malloc(sizeof(apermon_hash));
    memset(h, 0, sizeof(apermon_hash));
    h->hash_key_bits = hash_key_bits;
    h->hash_mask = (1 << hash_key_bits) - 1;
    h->items = calloc(h->hash_mask + 1, sizeof(apermon_hash_item *));

    return h;
}

void free_hash(apermon_hash *hash, const hash_element_freer_func freer) {
        apermon_hash_item *item, *prev = NULL;

    if (hash == NULL) {
        return;
    }

    item = hash->head;
    while (item != NULL) {
        if (prev != NULL) {
            free(prev);
        }

        if (item->key != NULL) {
            free(item->key);
        }

        if (freer != NULL) {
            freer(item->value);
        }

        prev = item;
        item = item->iter_next;
    }

    if (prev != NULL) {
        free(prev);
    }

    free(hash->items);
    free(hash);
}