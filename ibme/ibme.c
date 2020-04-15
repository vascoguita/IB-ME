#include <pbc/pbc.h>
#include <string.h>

#include "ibme.h"
#include "hash.h"
#include "keys.h"
#include "cipher.h"

int setup(MKP **mkp) {
    if(*mkp == NULL){
        return 1;
    }
    element_random((*mkp)->msk->r);
    element_random((*mkp)->msk->s);
    element_random((*mkp)->mpk->P);
    //TODO Find adequate arithmetic operation. It might be element_mul_zn(mpk->P0, P, r) instead
    element_pow_zn((*mkp)->mpk->P0, (*mkp)->mpk->P, (*mkp)->msk->r);
    return 0;
}

int sk_gen(const MKP *mkp, const unsigned char *S, size_t S_len, EK **ek) {
    Hash_G1 *hash;

    if((mkp == NULL) || (S == NULL) || (*ek == NULL)) {
        return 1;
    }

    if(1 == Hash_G1_init(mkp->mpk->pairing, &hash)) {
        return 1;
    }

    if(1 == H_prime(S, S_len, &hash)) {
        Hash_G1_clear(hash);
        return 1;
    }

    element_pow_zn((*ek)->k, hash->h, mkp->msk->s);

    Hash_G1_clear(hash);
    return 0;
}

int rk_gen(const MKP *mkp, const unsigned char *R, size_t R_len, DK **dk) {
    if((mkp == NULL) || (R == NULL) || (*dk == NULL)) {
        return 1;
    }

    if(1 == H(R, R_len, &((*dk)->k3)) ){
        return 1;
    }

    element_pow_zn((*dk)->k1, (*dk)->k3->h, mkp->msk->r);
    element_pow_zn((*dk)->k2, (*dk)->k3->h, mkp->msk->s);
    return 0;
}

int enc(MPK *mpk, EK *ek, const unsigned char *R, size_t R_len, const unsigned char *m, size_t m_len, Cipher **c){
    element_t u, t, P0_u, k_R, k_S, T_ek;
    Hash_G1 *h_R;
    Hash_bytes *h_k_R, *h_k_S;

    if((mpk == NULL) || (ek == NULL) || (R == NULL) || (R_len < 1) || (m == NULL) || (m_len < 1) || (*c == NULL)) {
        return 1;
    }

    element_init_Zr(u, mpk->pairing);
    element_init_Zr(t, mpk->pairing);
    element_random(u);
    element_random(t);

    element_pow_zn((*c)->T, mpk->P, t);
    element_pow_zn((*c)->U, mpk->P, u);
    element_clear(t);

    element_init_G1(P0_u, mpk->pairing);
    element_pow_zn(P0_u, mpk->P0, u);
    element_clear(u);
    if(1 == Hash_G1_init(mpk->pairing, &h_R)) {
        element_clear(P0_u);
        return 1;
    }
    if(1 == H(R, R_len, &h_R)) {
        element_clear(P0_u);
        Hash_G1_clear(h_R);
        return 1;
    }
    element_init_GT(k_R, mpk->pairing);
    element_pairing(k_R, h_R->h, P0_u);
    element_clear(P0_u);

    //TODO Find adequate group. It might be element_init_Zr(T_ek, mpk->pairing); instead
    element_init_G1(T_ek, mpk->pairing);
    //TODO Find adequate arithmetic operation. It might be element_mul_zn(T_ek, (*c)->T, ek->k) or element_add(T_ek, (*c)->T, ek->k); instead
    element_mul(T_ek, (*c)->T, ek->k);
    element_init_GT(k_S, mpk->pairing);
    element_pairing(k_S, h_R->h, T_ek);
    element_clear(T_ek);
    Hash_G1_clear(h_R);

    if(1 == Hash_bytes_init(k_R, &h_k_R)) {
        element_clear(k_S);
        element_clear(k_R);
        return 1;
    }
    if(1 == H_caret(k_R, &h_k_R)) {
        Hash_bytes_clear(h_k_R);
        element_clear(k_S);
        element_clear(k_R);
        return 1;
    }
    element_clear(k_R);

    if(1 == Hash_bytes_init(k_S, &h_k_S)) {
        Hash_bytes_clear(h_k_R);
        element_clear(k_S);
        return 1;
    }
    if(1 == H_caret(k_S, &h_k_S)) {
        Hash_bytes_clear(h_k_R);
        Hash_bytes_clear(h_k_S);
        element_clear(k_S);
        return 1;
    }
    element_clear(k_S);

    if(m_len > h_k_R->len || m_len > h_k_S->len || m_len > (*c)->V_len) {
        Hash_bytes_clear(h_k_R);
        Hash_bytes_clear(h_k_S);
        return 1;
    }
    for(((*c)->V_len) = 0; ((*c)->V_len) < m_len; ((*c)->V_len)++) {
        ((*c)->V)[((*c)->V_len)] = m[((*c)->V_len)] ^ (h_k_R->h)[((*c)->V_len)] ^ (h_k_S->h)[((*c)->V_len)];
    }

    Hash_bytes_clear(h_k_R);
    Hash_bytes_clear(h_k_S);
    return 0;
}

int dec(MPK *mpk, DK *dk, const unsigned char *S, size_t S_len, Cipher *c, unsigned char **m, size_t *m_len) {
    element_t k_R, k_S, k_S1, k_S2;
    Hash_G1 *h_S;
    Hash_bytes *h_k_R, *h_k_S;

    if((mpk == NULL) || (dk == NULL) || (S == NULL) || (S_len < 1) || (c == NULL) || (*m == NULL)) {
        return 1;
    }

    element_init_GT(k_R, mpk->pairing);
    element_pairing(k_R, dk->k1, c->U);

    if(1 == Hash_G1_init(mpk->pairing, &h_S)) {
        element_clear(k_R);
        return 1;
    }
    if(1 == H_prime(S, S_len, &h_S)) {
        element_clear(k_R);
        Hash_G1_clear(h_S);
        return 1;
    }

    //TODO Find adequate group. It might be element_init_G1(k_S1, mpk->pairing); instead
    element_init_GT(k_S1, mpk->pairing);
    element_pairing(k_S1, dk->k2, h_S->h);
    Hash_G1_clear(h_S);

    //TODO Find adequate group. It might be element_init_G1(k_S2, mpk->pairing); instead
    element_init_GT(k_S2, mpk->pairing);
    element_pairing(k_S2, dk->k3->h, c->T);

    element_init_GT(k_S, mpk->pairing);
    element_mul(k_S, k_S1, k_S2);
    element_clear(k_S2);
    element_clear(k_S1);

    if(1 == Hash_bytes_init(k_R, &h_k_R)) {
        element_clear(k_S);
        element_clear(k_R);
        return 1;
    }
    if(1 == H_caret(k_R, &h_k_R)) {
        Hash_bytes_clear(h_k_R);
        element_clear(k_S);
        element_clear(k_R);
        return 1;
    }
    element_clear(k_R);

    if(1 == Hash_bytes_init(k_S, &h_k_S)) {
        Hash_bytes_clear(h_k_R);
        element_clear(k_S);
        return 1;
    }
    if(1 == H_caret(k_S, &h_k_S)) {
        Hash_bytes_clear(h_k_R);
        Hash_bytes_clear(h_k_S);
        element_clear(k_S);
        return 1;
    }
    element_clear(k_S);

    if(c->V_len > h_k_R->len || c->V_len > h_k_S->len || c->V_len > *m_len) {
        Hash_bytes_clear(h_k_R);
        Hash_bytes_clear(h_k_S);
        return 1;
    }
    for(*m_len = 0; *m_len < c->V_len; (*m_len)++) {
        (*m)[*m_len] = (c->V)[*m_len] ^ (h_k_R->h)[*m_len] ^ (h_k_S->h)[*m_len];
    }

    Hash_bytes_clear(h_k_R);
    Hash_bytes_clear(h_k_S);
    return 0;
}