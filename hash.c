#include <string.h>
#include <stdlib.h>
#include "hash.h"

static inline uint32_t hash32(const uint32_t *buf) {
    return __builtin_ia32_crc32si(0, *buf) & HASH_MASK;
}

static inline uint32_t hash128(const uint8_t *buf) {
    uint32_t res = 0, i;
    for (i = 0; i < 16 / sizeof(uint32_t); ++i, buf += 4) {
        res = __builtin_ia32_crc32si(res, * (uint32_t *) buf);
    }

    return res & HASH_MASK;
}

static inline apermon_hash_item *_hash_find(apermon_hash *tbl, uint32_t hashed_key, const uint8_t *key, size_t key_len, apermon_hash_item **last) {
    apermon_hash_item *item = tbl->items[hashed_key], *target = NULL, *prev = NULL;

    while (item != NULL) {
        if (item->key_len != key_len) {
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

static inline apermon_hash_item *_hash_add_or_update(apermon_hash *tbl, uint32_t hashed_key, const uint8_t *key, size_t key_len, void *value, void **old_value) {
    apermon_hash_item *target, *prev = NULL;

    target = _hash_find(tbl, hashed_key, key, key_len, &prev);

    if (target != NULL) {
        *old_value = target->value;
        target->value = value;

        return target;
    }

    apermon_hash_item *item = (apermon_hash_item *) malloc(sizeof(apermon_hash_item));

    item->key_len = key_len;
    item->key = malloc(key_len);
    memcpy(item->key, key, key_len);
    item->value = value;
    item->next = NULL;

    if (prev == NULL) {
        tbl->items[hashed_key] = item;
    } else {
        prev->next = item;
    }

    return item;
}

apermon_hash_item *hash32_add_or_update(apermon_hash *tbl, const uint32_t *key, void *value, void **old_value) {
    return _hash_add_or_update(tbl, hash32(key), (uint8_t *) key, sizeof(uint32_t), value, old_value);
}

apermon_hash_item *hash128_add_or_update(apermon_hash *tbl, const uint8_t *key, void *value, void **old_value) {
    return _hash_add_or_update(tbl, hash128(key), key, 16 * sizeof(uint8_t), value, old_value);
}

apermon_hash_item *hash32_find(apermon_hash *tbl, const uint32_t *key) {
    return _hash_find(tbl, hash32(key), (uint8_t *) key, sizeof(uint32_t), NULL);
}

apermon_hash_item *hash128_find(apermon_hash *tbl, const uint8_t *key) {
    return _hash_find(tbl, hash128(key), key, 16 * sizeof(uint8_t), NULL);
}

apermon_hash *new_hash() {
    apermon_hash *h = (apermon_hash *) malloc(sizeof(apermon_hash));
    memset(h, 0, sizeof(apermon_hash));

    return h;
}

void free_hash(apermon_hash *hash) {
    size_t i;
    apermon_hash_item *item, *prev;

    for (i = 0; i < sizeof(hash->items) / sizeof(*hash->items); ++i) {
        prev = NULL;
        item = hash->items[i];
        if (item == NULL) {
            continue;
        }

        while (item != NULL) {
            if (prev != NULL) {
                free(prev);
            }

            if (item->key != NULL) {
                free (item->key);
            }

            prev = item;
            item = item->next;
        }

        if (prev != NULL) {
            free(prev);
        }
    }

    free(hash);
}