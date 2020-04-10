#include "hash.h"
#include <openssl/evp.h>
#include <string.h>
#include <pbc/pbc.h>

int H_prime(const unsigned char *X, size_t X_len, pairing_t pairing, Hash **hash) {
    unsigned char *_X;
    int i;

    if(X_len > mask_len) {
        return 1;
    }

    _X = (unsigned char *)malloc(X_len * sizeof(unsigned char));

    for(i = 0; i < X_len; i++) {
        _X[i] = X[i] ^ mask[i];
    }

    H(_X, X_len, pairing, hash);

    free(_X);
    return 0;
}

int H(const unsigned char *X, size_t X_len, pairing_t pairing, Hash **hash) {
    unsigned char *digest;
    unsigned int digest_len;
    EVP_MD_CTX *mdctx;

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

Hash *Hash_init(pairing_t pairing) {
    Hash *hash;
    hash = (struct _hash*) malloc(sizeof(struct _hash));
    element_init_G1(hash->h, pairing);
    return hash;
};

void Hash_clear(Hash *hash) {
    element_clear(hash->h);
    free(hash);
}