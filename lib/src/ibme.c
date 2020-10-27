#include <pbc/pbc.h>

#include "ibme.h"
#include "hash.h"
#include "keys.h"
#include "cipher.h"
#include "padding.h"
#include <stdlib.h>

#ifdef DEBUG
#include <tee_internal_api.h>
#endif

int ibme_setup(MKP *mkp) {
    #ifdef DEBUG
    char *mkp_str;
    size_t mkp_str_size;
    #endif

    if(mkp == NULL){
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

int ibme_sk_gen(pairing_t pairing, MSK *msk, const unsigned char *S, size_t S_size, EK *ek) {
    Hash_G1 *hash;

    #ifdef DEBUG
    char *ek_str;
    size_t ek_str_size;
    #endif

    if((pairing == NULL) || (msk == NULL) || (S == NULL) || (S_size < 1) || (ek == NULL)) {
        return 1;
    }

    if(1 == Hash_G1_init(pairing, &hash)) {
        return 1;
    }

    if(1 == H_prime(S, S_size, hash)) {
        Hash_G1_clear(hash);
        return 1;
    }

    element_pow_zn(ek->k, hash->h, msk->s);

    Hash_G1_clear(hash);

    #ifdef DEBUG
    ek_str_size = EK_snprint(NULL, 0, ek) + 1;
    ek_str = malloc(ek_str_size);
    EK_snprint(ek_str, ek_str_size, ek);
    DMSG("%s\n", ek_str);
    free(ek_str);
    #endif

    return 0;
}

int ibme_rk_gen(MSK *msk, const unsigned char *R, size_t R_size, DK *dk) {
    #ifdef DEBUG
    char *dk_str;
    size_t dk_str_size;
    #endif

    if((msk == NULL) || (R == NULL) || (R_size < 1) || (dk == NULL)) {
        return 1;
    }

    if(1 == H(R, R_size, dk->k3) ){
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

int ibme_enc(pairing_t pairing, MPK *mpk, EK *ek, const unsigned char *R, size_t R_size, const unsigned char *m, size_t m_size, Cipher *c){
    element_t u, t, P0_u, k_R, k_S, T_ek;
    Hash_G1 *h_R;
    Hash_bytes *h_k_R, *h_k_S;
    uint8_t *m_padded;
    size_t m_padded_size, tmp_bs;
    uint8_t bs;
    #ifdef DEBUG
    char *cipher_str;
    size_t cipher_str_size;
    #endif

    if((pairing == NULL) || (mpk == NULL) || (ek == NULL) || (R == NULL) || (R_size < 1) || (m == NULL) || (m_size < 1) || (c == NULL)) {
        return 1;
    }

    element_init_Zr(u, pairing);
    element_init_Zr(t, pairing);
    element_random(u);
    element_random(t);

    element_pow_zn(c->T, mpk->P, t);
    element_pow_zn(c->U, mpk->P, u);
    element_clear(t);

    element_init_G1(P0_u, pairing);
    element_pow_zn(P0_u, mpk->P0, u);
    element_clear(u);
    if(1 == Hash_G1_init(pairing, &h_R)) {
        element_clear(P0_u);
        return 1;
    }
    if(1 == H(R, R_size, h_R)) {
        element_clear(P0_u);
        Hash_G1_clear(h_R);
        return 1;
    }
    element_init_GT(k_R, pairing);
    element_pairing(k_R, h_R->h, P0_u);
    element_clear(P0_u);

    element_init_G1(T_ek, pairing);
    element_mul(T_ek, c->T, ek->k);
    element_init_GT(k_S, pairing);
    element_pairing(k_S, h_R->h, T_ek);
    element_clear(T_ek);
    Hash_G1_clear(h_R);

    if(1 == Hash_bytes_init(pairing, &h_k_R)) {
        element_clear(k_S);
        element_clear(k_R);
        return 1;
    }
    if(1 == H_caret(k_R, h_k_R)) {
        Hash_bytes_clear(h_k_R);
        element_clear(k_S);
        element_clear(k_R);
        return 1;
    }
    element_clear(k_R);

    if(1 == Hash_bytes_init(pairing, &h_k_S)) {
        Hash_bytes_clear(h_k_R);
        element_clear(k_S);
        return 1;
    }
    if(1 == H_caret(k_S, h_k_S)) {
        Hash_bytes_clear(h_k_R);
        Hash_bytes_clear(h_k_S);
        element_clear(k_S);
        return 1;
    }
    element_clear(k_S);

    tmp_bs = h_k_S->len < h_k_R->len ? h_k_S->len : h_k_R->len;
    bs = 0xff < tmp_bs ? 0xff : (uint8_t)tmp_bs;

    m_padded_size = 0;
    if(pad(m, m_size, bs, NULL, &m_padded_size) != 0) {
        Hash_bytes_clear(h_k_R);
        Hash_bytes_clear(h_k_S);
        return 1;
    }
    if(!(m_padded = malloc(m_padded_size))) {
        Hash_bytes_clear(h_k_R);
        Hash_bytes_clear(h_k_S);
        return 1;
    }
    if(pad(m, m_size, bs, m_padded, &m_padded_size) != 0) {
        free(m_padded);
        Hash_bytes_clear(h_k_R);
        Hash_bytes_clear(h_k_S);
        return 1;
    }

    if((m_padded_size > c->V_size) || (m_padded_size > h_k_R->len) || (m_padded_size > h_k_S->len)) {
        free(m_padded);
        Hash_bytes_clear(h_k_R);
        Hash_bytes_clear(h_k_S);
        return 1;
    }
    for(c->V_size = 0; c->V_size < m_padded_size; c->V_size++) {
        c->V[c->V_size] = m_padded[c->V_size] ^ h_k_R->h[c->V_size] ^ h_k_S->h[c->V_size];
    }

    free(m_padded);
    Hash_bytes_clear(h_k_R);
    Hash_bytes_clear(h_k_S);

    #ifdef DEBUG
    cipher_str_size = Cipher_snprint(NULL, 0, c) + 1;
    cipher_str = malloc(cipher_str_size);
    Cipher_snprint(cipher_str, cipher_str_size, c);
    DMSG("%s\n", cipher_str);
    free(cipher_str);
    #endif

    return 0;
}

int ibme_dec(pairing_t pairing, DK *dk, const unsigned char *S, size_t S_size, Cipher *c, unsigned char *m, size_t *m_size) {
    element_t k_R, k_S, k_S1, k_S2;
    Hash_G1 *h_S;
    Hash_bytes *h_k_R, *h_k_S;
    uint8_t *m_padded;
    size_t m_padded_size, tmp_bs;
    uint8_t bs;

    if((pairing == NULL) || (dk == NULL) || (S == NULL) || (S_size < 1) || (c == NULL)) {
        return 1;
    }

    element_init_GT(k_R, pairing);
    element_pairing(k_R, dk->k1, c->U);

    if(1 == Hash_G1_init(pairing, &h_S)) {
        element_clear(k_R);
        return 1;
    }
    if(1 == H_prime(S, S_size, h_S)) {
        element_clear(k_R);
        Hash_G1_clear(h_S);
        return 1;
    }

    element_init_GT(k_S1, pairing);
    element_pairing(k_S1, dk->k2, h_S->h);
    Hash_G1_clear(h_S);

    element_init_GT(k_S2, pairing);
    element_pairing(k_S2, dk->k3->h, c->T);

    element_init_GT(k_S, pairing);
    element_mul(k_S, k_S1, k_S2);
    element_clear(k_S2);
    element_clear(k_S1);

    if(1 == Hash_bytes_init(pairing, &h_k_R)) {
        element_clear(k_S);
        element_clear(k_R);
        return 1;
    }
    if(1 == H_caret(k_R, h_k_R)) {
        Hash_bytes_clear(h_k_R);
        element_clear(k_S);
        element_clear(k_R);
        return 1;
    }
    element_clear(k_R);

    if(1 == Hash_bytes_init(pairing, &h_k_S)) {
        Hash_bytes_clear(h_k_R);
        element_clear(k_S);
        return 1;
    }
    if(1 == H_caret(k_S, h_k_S)) {
        Hash_bytes_clear(h_k_R);
        Hash_bytes_clear(h_k_S);
        element_clear(k_S);
        return 1;
    }
    element_clear(k_S);

    if((c->V_size > h_k_R->len) || (c->V_size > h_k_S->len)) {
        Hash_bytes_clear(h_k_R);
        Hash_bytes_clear(h_k_S);
        return 1;
    }

    if(!(m_padded = malloc(c->V_size))) {
        Hash_bytes_clear(h_k_R);
        Hash_bytes_clear(h_k_S);
        return 1;
    }

    for(m_padded_size = 0; m_padded_size < c->V_size; m_padded_size++) {
        m_padded[m_padded_size] = c->V[m_padded_size] ^ h_k_R->h[m_padded_size] ^ h_k_S->h[m_padded_size];
    }

    tmp_bs = h_k_S->len < h_k_R->len ? h_k_S->len : h_k_R->len;
    bs = 0xff < tmp_bs ? 0xff : (uint8_t)tmp_bs;

    Hash_bytes_clear(h_k_R);
    Hash_bytes_clear(h_k_S);

    if(unpad(m_padded, m_padded_size, bs, m, m_size) != 0){
        free(m_padded);
        return 1;
    }

    free(m_padded);
    return 0;
}