#include "hash.h"
#include <mbedtls/sha256.h>
#include <string.h>
#include <pbc.h>
#include "memory.h"
#include "utils.h"

int H_caret(element_t e, Hash_bytes *hash){
    int e_bytes_len, hash_bytes_len;
    unsigned char *e_bytes;

    e_bytes_len = element_length_in_bytes(e);
    hash_bytes_len = Hash_bytes_length(e_bytes_len);

    if((e == NULL) || (hash == NULL) || (hash->len < hash_bytes_len)) {
        return 1;
    }

    if((e_bytes = (unsigned char *) ibme_malloc(e_bytes_len * sizeof(unsigned char))) == NULL) {
        return 1;
    }

    if(element_to_bytes(e_bytes, e) != e_bytes_len) {
        ibme_free(e_bytes);
        return 1;
    }

    //hash->h = e_bytes[2:-1]
    //TODO: improve
    for(hash->len = 0; (hash->len < hash_bytes_len) && ((hash->len + 2) < e_bytes_len); (hash->len)++) {
        hash->h[hash->len] = e_bytes[hash->len + 2];
    }

    ibme_free(e_bytes);
    return 0;
}

int H_prime(const unsigned char *X, size_t X_len, Hash_G1 *hash) {
    unsigned char *_X;
    int i;

    if((X == NULL) || (X_len < 1) || (X_len > mask_len) || (hash == NULL)) {
        return 1;
    }

    if ((_X = (unsigned char *)ibme_malloc(X_len * sizeof(unsigned char))) == NULL) {
        return 1;
    }

    for(i = 0; i < X_len; i++) {
        _X[i] = X[i] ^ mask[i];
    }

    if(1 == H(_X, X_len, hash)) {
        ibme_free(_X);
        return 1;
    }

    ibme_free(_X);
    return 0;
}

int H(const unsigned char *X, size_t X_len, Hash_G1 *hash) {
    unsigned char digest[sha256_digest_len];

    if ((X == NULL) || (X_len < 1) || (hash == NULL)) {
        return 1;
    }

    if (1 == mbedtls_sha256_ret(X, X_len, digest, 0)) {
        return 1;
    }

    element_from_hash(hash->h, digest, sha256_digest_len);

    return 0;
}

int Hash_bytes_length_from_pairing(pairing_t pairing) {
    return Hash_bytes_length(pairing_length_in_bytes_GT(pairing));
}

int Hash_bytes_length(int e_bytes_len) {
    return e_bytes_len - 3;
}

int Hash_G1_init(pairing_t pairing, Hash_G1 **hash) {
    if((*hash = (struct _hash_g1*) ibme_malloc(sizeof(struct _hash_g1))) == NULL) {
        return 1;
    }
    element_init_G1((*hash)->h, pairing);
    if(((*hash)->h) == NULL) {
        Hash_G1_clear(*hash);
        return 1;
    }
    return 0;
};

void Hash_G1_clear(Hash_G1 *hash) {
    if(hash != NULL) {
        element_clear(hash->h);
        ibme_free(hash);
    }
}

int Hash_G1_snprint(char *s, size_t n, Hash_G1 *hash) {
    size_t result, left;
    int status;

    result = 0;

    status = snprintf(s, n, "[");
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = element_snprint(s + result, left, hash->h);
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, "]");
    if (status < 0) {
        return status;
    }
    return (int)result + status;
}

int Hash_G1_set_str(char *s, size_t n, Hash_G1 *hash) {
    size_t result, left;
    int status;

    result = 0;

    status = strlen("[");
    if(strncmp(s, "[", status) != 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if((status = element_set_str(hash->h, s + result, 10)) == 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    status = strlen("]");
    if(strncmp(s + result, "]", status) != 0) {
        return 0;
    }

    return (int)result + status;
}

int Hash_bytes_init(pairing_t pairing, Hash_bytes **hash) {
    if((*hash = (struct _hash_bytes*) ibme_malloc(sizeof(struct _hash_bytes))) == NULL) {
        return 1;
    }
    if(((*hash)->len = Hash_bytes_length_from_pairing(pairing)) < 1) {
        Hash_bytes_clear(*hash);
        return 1;
    }
    if(((*hash)->h = (unsigned char *) ibme_malloc((*hash)->len * sizeof(unsigned char))) == NULL) {
        Hash_bytes_clear(*hash);
        return 1;
    }
    return 0;
}

void Hash_bytes_clear(Hash_bytes *hash) {
    if(hash != NULL) {
        ibme_free(hash->h);
        ibme_free(hash);
    }
}