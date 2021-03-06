#include <pbc/pbc.h>

#include "ibme.h"
#include "hash.h"
#include "keys.h"
#include "cipher.h"
#include "padding.h"

int setup(MKP *mkp) {
    if(mkp == NULL){
        return 1;
    }
    element_random(mkp->msk->r);
    element_random(mkp->msk->s);
    element_random(mkp->mpk->P);
    element_pow_zn(mkp->mpk->P0, mkp->mpk->P, mkp->msk->r);

    #if DEBUG
    element_printf("mpk:\n%B\n%B\nmsk:\n%B\n%B\n", mkp->mpk->P, mkp->mpk->P0, mkp->msk->r, mkp->msk->s);
    #endif

    return 0;
}

int sk_gen(pairing_t pairing, MSK *msk, const unsigned char *S, size_t S_len, EK *ek) {
    Hash_G1 *hash;

    if((pairing == NULL) || (msk == NULL) || (S == NULL) || (S_len < 1) || (ek == NULL)) {
        return 1;
    }

    if(1 == Hash_G1_init(pairing, &hash)) {
        return 1;
    }

    if(1 == H_prime(S, S_len, hash)) {
        Hash_G1_clear(hash);
        return 1;
    }

    element_pow_zn(ek->k, hash->h, msk->s);

    Hash_G1_clear(hash);

    #if DEBUG
    element_printf("ek of \"%s\":\n%B\n", S, ek->k);
    #endif

    return 0;
}

int rk_gen(MSK *msk, const unsigned char *R, size_t R_len, DK *dk) {
    if((msk == NULL) || (R == NULL) || (R_len < 1) || (dk == NULL)) {
        return 1;
    }

    if(1 == H(R, R_len, dk->k3) ){
        return 1;
    }

    element_pow_zn(dk->k1, dk->k3->h, msk->r);
    element_pow_zn(dk->k2, dk->k3->h, msk->s);

    #if DEBUG
    element_printf("dk of \"%s\":\n%B\n%B\n%B\n", R, dk->k1, dk->k2, dk->k3->h);
    #endif

    return 0;
}

int enc(pairing_t pairing, MPK *mpk, EK *ek, const unsigned char *R, size_t R_len, const unsigned char *m, size_t m_len, Cipher *c){
    element_t u, t, P0_u, k_R, k_S, T_ek;
    Hash_G1 *h_R;
    Hash_bytes *h_k_R, *h_k_S;
    Padded_data *m_padded;
    #if DEBUG
    int i;
    #endif


    if((pairing == NULL) || (mpk == NULL) || (ek == NULL) || (R == NULL) || (R_len < 1) || (m == NULL) || (m_len < 1) || (c == NULL)) {
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
    if(1 == H(R, R_len, h_R)) {
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

    if(1 == Padded_data_init(h_k_S->len, &m_padded)) {
        Hash_bytes_clear(h_k_R);
        Hash_bytes_clear(h_k_S);
        return 1;
    }
    if(1 == pad(m, m_len, m_padded)){
        Hash_bytes_clear(h_k_R);
        Hash_bytes_clear(h_k_S);
        Padded_data_clear(m_padded);
        return 1;
    }

    if((m_padded->len > c->V_len) || (m_padded->len > h_k_R->len) || (m_padded->len > h_k_S->len)) {
        Hash_bytes_clear(h_k_R);
        Hash_bytes_clear(h_k_S);
        Padded_data_clear(m_padded);
        return 1;
    }
    for(c->V_len = 0; c->V_len < m_padded->len; c->V_len++) {
        c->V[c->V_len] = m_padded->p_d[c->V_len] ^ h_k_R->h[c->V_len] ^ h_k_S->h[c->V_len];
    }

    Padded_data_clear(m_padded);
    Hash_bytes_clear(h_k_R);
    Hash_bytes_clear(h_k_S);

    #if DEBUG
    element_printf("cipher of \"%s\" to \"%s\":\n%B\n%B\n", m, R, c->T, c->U);
    for(i = 0; i < c->V_len; i++) {
        printf("\\x%x", c->V[i]);
    }
    printf("\n");
    #endif

    return 0;
}

int dec(pairing_t pairing, DK *dk, const unsigned char *S, size_t S_len, Cipher *c, unsigned char *m, size_t *m_len) {
    element_t k_R, k_S, k_S1, k_S2;
    Hash_G1 *h_S;
    Hash_bytes *h_k_R, *h_k_S;
    Padded_data *m_padded;

    if((pairing == NULL) || (dk == NULL) || (S == NULL) || (S_len < 1) || (c == NULL) || (m == NULL)) {
        return 1;
    }

    element_init_GT(k_R, pairing);
    element_pairing(k_R, dk->k1, c->U);

    if(1 == Hash_G1_init(pairing, &h_S)) {
        element_clear(k_R);
        return 1;
    }
    if(1 == H_prime(S, S_len, h_S)) {
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

    if(1 == Padded_data_init(h_k_S->len, &m_padded)) {
        Hash_bytes_clear(h_k_R);
        Hash_bytes_clear(h_k_S);
        return 1;
    }

    if((c->V_len > h_k_R->len) || (c->V_len > h_k_S->len) || (c->V_len > m_padded->len)) {
        Padded_data_clear(m_padded);
        Hash_bytes_clear(h_k_R);
        Hash_bytes_clear(h_k_S);
        return 1;
    }

    for(m_padded->len = 0; m_padded->len < c->V_len; m_padded->len++) {
        m_padded->p_d[m_padded->len] = c->V[m_padded->len] ^ h_k_R->h[m_padded->len] ^ h_k_S->h[m_padded->len];
    }
    Hash_bytes_clear(h_k_R);
    Hash_bytes_clear(h_k_S);

    if(1 == unpad(m_padded, m, m_len)){
        Padded_data_clear(m_padded);
        return 1;
    }

    Padded_data_clear(m_padded);
    return 0;
}