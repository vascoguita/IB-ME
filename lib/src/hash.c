#include "hash.h"
#include <tee_internal_api.h>
#include <utee_defines.h>
#include <string.h>
#include <pbc/pbc.h>
#include <stdlib.h>
#include "utils.h"

int H_caret(element_t e, Hash_bytes *hash)
{
    int e_bytes_len, hash_bytes_len;
    unsigned char *e_bytes;

    e_bytes_len = element_length_in_bytes(e);
    hash_bytes_len = Hash_bytes_length(e_bytes_len);

    if ((e == NULL) || (hash == NULL) || (hash->len < (size_t)hash_bytes_len))
    {
        return 1;
    }

    if ((e_bytes = (unsigned char *)malloc(e_bytes_len * sizeof(unsigned char))) == NULL)
    {
        return 1;
    }

    if (element_to_bytes(e_bytes, e) != e_bytes_len)
    {
        free(e_bytes);
        return 1;
    }

    //TODO: improve
    for (hash->len = 0; (hash->len < (size_t)hash_bytes_len) && ((hash->len + 2) < (size_t)e_bytes_len); (hash->len)++)
    {
        hash->h[hash->len] = e_bytes[hash->len + 2];
    }

    free(e_bytes);
    return 0;
}

int H_prime(const unsigned char *X, size_t X_len, Hash_G1 *hash)
{
    unsigned char *_X;
    int i;

    if ((X == NULL) || (X_len < 1) || (X_len > mask_len) || (hash == NULL))
    {
        return 1;
    }

    if ((_X = (unsigned char *)malloc(X_len * sizeof(unsigned char))) == NULL)
    {
        return 1;
    }

    for (i = 0; (size_t)i < X_len; i++)
    {
        _X[i] = X[i] ^ mask[i];
    }

    if (1 == H(_X, X_len, hash))
    {
        free(_X);
        return 1;
    }

    free(_X);
    return 0;
}

int H(const unsigned char *X, size_t X_len, Hash_G1 *hash)
{   
    TEE_Result res;
    TEE_OperationHandle op_handle;
    unsigned char h[TEE_SHA256_HASH_SIZE];
    uint32_t h_size = TEE_SHA256_HASH_SIZE;

    if ((X == NULL) || (X_len < 1) || (hash == NULL))
    {
        return 1;
    }

    res = TEE_AllocateOperation(&op_handle, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
    if (res != TEE_SUCCESS)
    {
        return 1;
    }
    res = TEE_DigestDoFinal(op_handle, X, X_len, h, &h_size);
    if (res != TEE_SUCCESS)
    {
        TEE_FreeOperation(op_handle);
        return 1;
    }
    TEE_FreeOperation(op_handle);

    element_from_hash(hash->h, h, h_size);

    return 0;
}

int Hash_bytes_length_from_pairing(pairing_t pairing)
{
    return Hash_bytes_length(pairing_length_in_bytes_GT(pairing));
}

int Hash_bytes_length(int e_bytes_len)
{
    return e_bytes_len - 3;
}

Hash_G1 *Hash_G1_init(pairing_t pairing)
{
    Hash_G1 *hash;
    if (!(hash = (struct _hash_g1 *)malloc(sizeof(struct _hash_g1))))
    {
        return NULL;
    }
    element_init_G1(hash->h, pairing);
    if (!(hash->h))
    {
        Hash_G1_clear(hash);
        return NULL;
    }
    return hash;
};

void Hash_G1_clear(Hash_G1 *hash)
{
    if (!hash)
    {
        element_clear(hash->h);
        free(hash);
    }
}

int Hash_G1_snprint(char *s, size_t n, Hash_G1 *hash)
{
    size_t result, left;
    int status;

    result = 0;

    status = snprintf(s, n, "[");
    if (status < 0)
    {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = element_snprint(s + result, left, hash->h);
    if (status < 0)
    {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, "]");
    if (status < 0)
    {
        return status;
    }
    return (int)result + status;
}

int Hash_G1_set_str(char *s, size_t n, Hash_G1 *hash)
{
    size_t result, left;
    int status;

    result = 0;

    status = strlen("[");
    if (strncmp(s, "[", status) != 0)
    {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if ((status = element_set_str(hash->h, s + result, 10)) == 0)
    {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    status = strlen("]");
    if (strncmp(s + result, "]", status) != 0)
    {
        return 0;
    }

    return (int)result + status;
}

Hash_bytes *Hash_bytes_init(pairing_t pairing)
{
    Hash_bytes *hash;
    if (!(hash = (struct _hash_bytes *)malloc(sizeof(struct _hash_bytes))))
    {
        return NULL;
    }
    if ((hash->len = Hash_bytes_length_from_pairing(pairing)) < 1)
    {
        Hash_bytes_clear(hash);
        return NULL;
    }
    if (!(hash->h = (unsigned char *)malloc(hash->len * sizeof(unsigned char))))
    {
        Hash_bytes_clear(hash);
        return NULL;
    }
    return hash;
}

void Hash_bytes_clear(Hash_bytes *hash)
{
    if (!hash)
    {
        free(hash->h);
        free(hash);
    }
}