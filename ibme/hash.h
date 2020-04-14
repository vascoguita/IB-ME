#ifndef IBME_HASH_H
#define IBME_HASH_H

#include <pbc/pbc.h>

typedef struct _hash_g1 {
    element_t h;
} Hash_G1;

typedef struct _hash_bytes {
    unsigned char *h;
    size_t len;
} Hash_bytes;

int Hash_G1_init(pairing_t pairing, Hash_G1 **hash);
void Hash_G1_clear(Hash_G1 *hash);

int Hash_bytes_init(element_t e, Hash_bytes **hash);
void Hash_bytes_clear(Hash_bytes *hash);

int H_caret(element_t e, Hash_bytes **hash);
int H_prime(const unsigned char *X, size_t X_len, Hash_G1 **hash);
int H(const unsigned char *X, size_t X_len, Hash_G1 **hash);

static const unsigned char mask[] = {
        0xed, 0x27, 0xdb, 0xfb, 0x02, 0x75, 0x2e, 0x0e, 0x16, 0xbc, 0x45, 0x02,
        0xd6, 0xc7, 0x32, 0xbc, 0x5f, 0x1c, 0xc9, 0x2b, 0xa1, 0x9b, 0x2d, 0x93,
        0xa4, 0xe9, 0x5c, 0x59, 0x7c, 0xa4, 0x27, 0x53, 0xe9, 0x35, 0x50, 0xb5,
        0x2f, 0x82, 0xb6, 0xc1, 0x3f, 0xb8, 0xcc, 0x0c, 0x2f, 0xc6, 0x44, 0x87
};
static const unsigned int mask_len = 48;

#endif //IBME_HASH_H
