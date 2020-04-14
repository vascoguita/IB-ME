#include "hash.h"
#include <openssl/evp.h>
#include <string.h>
#include <pbc/pbc.h>

int H_caret(element_t e, Hash_bytes **hash){
    int e_bytes_len, i;
    unsigned char *e_bytes;

    e_bytes_len = element_length_in_bytes(e);

    if((e == NULL) || (*hash == NULL) || ((*hash)->len != e_bytes_len - 3)) {
        return 1;
    }

    if((e_bytes = (unsigned char *) malloc(e_bytes_len * sizeof(unsigned char))) == NULL) {
        return 1;
    }

    if(element_to_bytes(e_bytes, e) != e_bytes_len) {
        free(e_bytes);
        return 1;
    }

    for(i = 0; i <  (*hash)->len; i++) {
        (*hash)->h[i] = e_bytes[i + 2];
    }

    free(e_bytes);
    return 0;
}

int H_prime(const unsigned char *X, size_t X_len, Hash_G1 **hash) {
    unsigned char *_X;
    int i;

    if((X == NULL) || (X_len < 1) || (X_len > mask_len) || (*hash == NULL)) {
        return 1;
    }

    if ((_X = (unsigned char *)malloc(X_len * sizeof(unsigned char))) == NULL) {
        return 1;
    }

    for(i = 0; i < X_len; i++) {
        _X[i] = X[i] ^ mask[i];
    }

    if(1 == H(_X, X_len, hash)) {
        free(_X);
        return 1;
    }

    free(_X);
    return 0;
}

int H(const unsigned char *X, size_t X_len, Hash_G1 **hash) {
    unsigned char *digest;
    unsigned int digest_len;
    EVP_MD_CTX *mdctx;

    if((X == NULL) || (X_len < 1) || (*hash == NULL)) {
        return 1;
    }

    if ((mdctx = EVP_MD_CTX_new()) == NULL) {
        return 1;
    }

    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) {
        EVP_MD_CTX_free(mdctx);
        return 1;
    }

    if(1 != EVP_DigestUpdate(mdctx, X, X_len)) {
        EVP_MD_CTX_free(mdctx);
        return 1;
    }

    if((digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()))) == NULL) {
        EVP_MD_CTX_free(mdctx);
        return 1;
    }

    if(1 != EVP_DigestFinal_ex(mdctx, digest, &digest_len)) {
        EVP_MD_CTX_free(mdctx);
        OPENSSL_free(digest);
        return 1;
    }

    EVP_MD_CTX_free(mdctx);

    element_from_hash((*hash)->h, digest, (int)digest_len);

    OPENSSL_free(digest);

    return 0;
}

int Hash_G1_init(pairing_t pairing, Hash_G1 **hash) {
    if((*hash = (struct _hash_g1*) malloc(sizeof(struct _hash_g1))) == NULL) {
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
    element_clear(hash->h);
    free(hash);
}

int Hash_bytes_init(element_t e, Hash_bytes **hash) {
    if((*hash = (struct _hash_bytes*) malloc(sizeof(struct _hash_bytes))) == NULL) {
        return 1;
    }
    if(((*hash)->len = element_length_in_bytes(e) - 3) < 1) {
        Hash_bytes_clear(*hash);
        return 1;
    }
    if(((*hash)->h = (unsigned char *)malloc((*hash)->len * sizeof(unsigned char))) == NULL) {
        Hash_bytes_clear(*hash);
        return 1;
    }
    return 0;
}

void Hash_bytes_clear(Hash_bytes *hash) {
    free(hash->h);
    free(hash);
}