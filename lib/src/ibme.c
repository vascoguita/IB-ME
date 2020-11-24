#include <pbc/pbc.h>

#include "ibme.h"
#include "hash.h"
#include "keys.h"
#include "cipher.h"
#include "padding.h"
#include <stdlib.h>
#include <tee_internal_api.h>
#include <utee_defines.h>

int ibme_setup(MKP *mkp)
{
#ifdef DEBUG
    char *mkp_str;
    size_t mkp_str_size;
#endif

    if (mkp == NULL)
    {
        return 1;
    }
    element_random(mkp->msk->r);
    element_random(mkp->msk->s);
    element_random(mkp->mpk->P);
    element_pow_zn(mkp->mpk->P0, mkp->mpk->P, mkp->msk->r);

#ifdef DEBUG
    mkp_str_size = MKP_snprint(NULL, 0, mkp) + 1;
    mkp_str = malloc(mkp_str_size);
    MKP_snprint(mkp_str, mkp_str_size, mkp);
    DMSG("%s\n", mkp_str);
    free(mkp_str);
#endif

    return 0;
}

int ibme_sk_gen(pairing_t pairing, MSK *msk, const unsigned char *S, size_t S_size, EK *ek)
{
    int ret = 0;
    Hash_G1 *hash = NULL;
#ifdef DEBUG
    char *ek_str;
    size_t ek_str_size;
#endif

    if ((pairing == NULL) || (msk == NULL) || (S == NULL) || (S_size < 1) || (ek == NULL))
    {
        ret = 1;
        goto out;
    }

    if (!(hash = Hash_G1_init(pairing)))
    {
        ret = 1;
        goto out;
    }

    if (1 == H_prime(S, S_size, hash))
    {
        ret = 1;
        goto out;
    }

    element_pow_zn(ek->k, hash->h, msk->s);

#ifdef DEBUG
    ek_str_size = EK_snprint(NULL, 0, ek) + 1;
    ek_str = malloc(ek_str_size);
    EK_snprint(ek_str, ek_str_size, ek);
    DMSG("%s\n", ek_str);
    free(ek_str);
#endif

out:
    Hash_G1_clear(hash);
    return ret;
}

int ibme_rk_gen(MSK *msk, const unsigned char *R, size_t R_size, DK *dk)
{
#ifdef DEBUG
    char *dk_str;
    size_t dk_str_size;
#endif

    if ((msk == NULL) || (R == NULL) || (R_size < 1) || (dk == NULL))
    {
        return 1;
    }

    if (1 == H(R, R_size, dk->k3))
    {
        return 1;
    }

    element_pow_zn(dk->k1, dk->k3->h, msk->r);
    element_pow_zn(dk->k2, dk->k3->h, msk->s);

#ifdef DEBUG
    dk_str_size = DK_snprint(NULL, 0, dk) + 1;
    dk_str = malloc(dk_str_size);
    DK_snprint(dk_str, dk_str_size, dk);
    DMSG("%s\n", dk_str);
    free(dk_str);
#endif

    return 0;
}

int ibme_enc(pairing_t pairing, MPK *mpk, EK *ek, const unsigned char *R, size_t R_size, const unsigned char *m, size_t m_size, Cipher *c)
{
    element_t u, t, P0_u, k_R, k_S, T_ek;
    Hash_G1 *h_R = NULL;
    Hash_bytes *h_k_R = NULL, *h_k_S = NULL;
    uint8_t *m_padded = NULL, *m_hashed = NULL, *m_hash;
    size_t m_padded_size, m_hashed_size, tmp_bs;
    uint32_t m_hash_size = TEE_SHA256_HASH_SIZE;
    TEE_Result res;
    TEE_OperationHandle op_handle = TEE_HANDLE_NULL;
    uint8_t bs;
    int ret = 0;
#ifdef DEBUG
    char *cipher_str;
    size_t cipher_str_size;
#endif

    if ((pairing == NULL) || (mpk == NULL) || (ek == NULL) || (R == NULL) || (R_size < 1) || (m == NULL) || (m_size < 1) || (c == NULL))
    {
        ret = 1;
        goto out;
    }

    element_init_Zr(u, pairing);
    element_init_Zr(t, pairing);
    element_random(u);
    element_random(t);

    element_pow_zn(c->T, mpk->P, t);
    element_pow_zn(c->U, mpk->P, u);

    element_init_G1(P0_u, pairing);
    element_pow_zn(P0_u, mpk->P0, u);
    if (!(h_R = Hash_G1_init(pairing)))
    {
        ret = 1;
        goto out;
    }
    if (1 == H(R, R_size, h_R))
    {
        ret = 1;
        goto out;
    }
    element_init_GT(k_R, pairing);
    element_pairing(k_R, h_R->h, P0_u);

    element_init_G1(T_ek, pairing);
    element_mul(T_ek, c->T, ek->k);
    element_init_GT(k_S, pairing);
    element_pairing(k_S, h_R->h, T_ek);

    if (!(h_k_R = Hash_bytes_init(pairing)))
    {
        ret = 1;
        goto out;
    }
    if (1 == H_caret(k_R, h_k_R))
    {
        ret = 1;
        goto out;
    }

    if (!(h_k_S = Hash_bytes_init(pairing)))
    {
        ret = 1;
        goto out;
    }
    if (1 == H_caret(k_S, h_k_S))
    {
        ret = 1;
        goto out;
    }

    m_hashed_size = m_size + m_hash_size;
    if (!(m_hashed = malloc(m_hashed_size)))
    {
        ret = 1;
        goto out;
    }
    memcpy(m_hashed, m, m_size);
    m_hash = m_hashed + m_size;

    res = TEE_AllocateOperation(&op_handle, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
    if (res != TEE_SUCCESS)
    {
        ret = 1;
        goto out;
    }
    res = TEE_DigestDoFinal(op_handle, m, m_size, m_hash, &m_hash_size);
    if (res != TEE_SUCCESS || m_hash_size != TEE_SHA256_HASH_SIZE)
    {
        ret = 1;
        goto out;
    }

    tmp_bs = h_k_S->len < h_k_R->len ? h_k_S->len : h_k_R->len;
    bs = 0xff < tmp_bs ? 0xff : (uint8_t)tmp_bs;

    m_padded_size = 0;
    if (pad(m_hashed, m_hashed_size, bs, NULL, &m_padded_size) != 0)
    {
        ret = 1;
        goto out;
    }
    if (!(m_padded = malloc(m_padded_size)))
    {
        ret = 1;
        goto out;
    }
    if (pad(m_hashed, m_hashed_size, bs, m_padded, &m_padded_size) != 0)
    {
        ret = 1;
        goto out;
    }

    if ((m_padded_size > c->V_size) || (m_padded_size > h_k_R->len) || (m_padded_size > h_k_S->len))
    {
        ret = 1;
        goto out;
    }
    for (c->V_size = 0; c->V_size < m_padded_size; c->V_size++)
    {
        c->V[c->V_size] = m_padded[c->V_size] ^ h_k_R->h[c->V_size] ^ h_k_S->h[c->V_size];
    }

#ifdef DEBUG
    cipher_str_size = Cipher_snprint(NULL, 0, c) + 1;
    cipher_str = malloc(cipher_str_size);
    Cipher_snprint(cipher_str, cipher_str_size, c);
    DMSG("%s\n", cipher_str);
    free(cipher_str);
#endif

out:
    free(m_padded);
    free(m_hashed);
    if (op_handle != TEE_HANDLE_NULL)
    {
        TEE_FreeOperation(op_handle);
    }
    Hash_bytes_clear(h_k_S);
    Hash_bytes_clear(h_k_R);
    element_clear(k_S);
    element_clear(T_ek);
    element_clear(k_R);
    Hash_G1_clear(h_R);
    element_clear(P0_u);
    element_clear(t);
    element_clear(u);
    return ret;
}

int ibme_dec(pairing_t pairing, DK *dk, const unsigned char *S, size_t S_size, Cipher *c, unsigned char *m, size_t *m_size)
{
    element_t k_R, k_S, k_S1, k_S2;
    Hash_G1 *h_S = NULL;
    Hash_bytes *h_k_R = NULL, *h_k_S = NULL;
    uint8_t *m_padded = NULL, *m_hashed = NULL;
    size_t m_padded_size, m_hashed_size, tmp_bs, tmp_m_size;
    unsigned char m_hash[TEE_SHA256_HASH_SIZE];
    uint32_t m_hash_size = TEE_SHA256_HASH_SIZE;
    TEE_Result res;
    TEE_OperationHandle op_handle = TEE_HANDLE_NULL;
    uint8_t bs;
    int ret = 0;

    if ((pairing == NULL) || (dk == NULL) || (S == NULL) || (S_size < 1) || (c == NULL))
    {
        ret = 1;
        goto out;
    }

    element_init_GT(k_R, pairing);
    element_pairing(k_R, dk->k1, c->U);

    if (!(h_S = Hash_G1_init(pairing)))
    {
        ret = 1;
        goto out;
    }
    if (1 == H_prime(S, S_size, h_S))
    {
        ret = 1;
        goto out;
    }

    element_init_GT(k_S1, pairing);
    element_pairing(k_S1, dk->k2, h_S->h);

    element_init_GT(k_S2, pairing);
    element_pairing(k_S2, dk->k3->h, c->T);

    element_init_GT(k_S, pairing);
    element_mul(k_S, k_S1, k_S2);

    if (!(h_k_R = Hash_bytes_init(pairing)))
    {
        ret = 1;
        goto out;
    }
    if (1 == H_caret(k_R, h_k_R))
    {
        ret = 1;
        goto out;
    }

    if (!(h_k_S = Hash_bytes_init(pairing)))
    {
        ret = 1;
        goto out;
    }
    if (1 == H_caret(k_S, h_k_S))
    {
        ret = 1;
        goto out;
    }

    if ((c->V_size > h_k_R->len) || (c->V_size > h_k_S->len))
    {
        ret = 1;
        goto out;
    }

    if (!(m_padded = malloc(c->V_size)))
    {
        ret = 1;
        goto out;
    }

    for (m_padded_size = 0; m_padded_size < c->V_size; m_padded_size++)
    {
        m_padded[m_padded_size] = c->V[m_padded_size] ^ h_k_R->h[m_padded_size] ^ h_k_S->h[m_padded_size];
    }

    tmp_bs = h_k_S->len < h_k_R->len ? h_k_S->len : h_k_R->len;
    bs = 0xff < tmp_bs ? 0xff : (uint8_t)tmp_bs;

    m_hashed_size = 0;
    if (unpad(m_padded, m_padded_size, bs, NULL, &m_hashed_size) != 0)
    {
        ret = 1;
        goto out;
    }
    if (!(m_hashed = malloc(m_hashed_size)))
    {
        ret = 1;
        goto out;
    }
    if (unpad(m_padded, m_padded_size, bs, m_hashed, &m_hashed_size) != 0)
    {
        ret = 1;
        goto out;
    }

    tmp_m_size = m_hashed_size - m_hash_size;

    res = TEE_AllocateOperation(&op_handle, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
    if (res != TEE_SUCCESS)
    {
        ret = 1;
        goto out;
    }
    res = TEE_DigestDoFinal(op_handle, m_hashed, tmp_m_size, m_hash, &m_hash_size);
    if (res != TEE_SUCCESS || m_hash_size != TEE_SHA256_HASH_SIZE)
    {
        ret = 1;
        goto out;
    }
    if (memcmp(m_hash, m_hashed + tmp_m_size, m_hash_size) != 0)
    {
        ret = 1;
        goto out;
    }

    if ((m == NULL) && (*m_size == 0))
    {
        *m_size = tmp_m_size;
        ret = 0;
        goto out;
    }
    if ((m == NULL) || (*m_size != tmp_m_size))
    {
        ret = 1;
        goto out;
    }
    memcpy(m, m_hashed, *m_size);

out:
    if (op_handle != TEE_HANDLE_NULL)
    {
        TEE_FreeOperation(op_handle);
    }
    free(m_hashed);
    free(m_padded);
    Hash_bytes_clear(h_k_S);
    Hash_bytes_clear(h_k_R);
    element_clear(k_S);
    element_clear(k_S2);
    element_clear(k_S1);
    Hash_G1_clear(h_S);
    element_clear(k_R);
    return ret;
}