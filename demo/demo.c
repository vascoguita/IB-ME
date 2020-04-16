#include <ibme.h>
#include <pbc/pbc.h>    //only required for debug with element_printf(...)
#include <string.h>
#include "demo.h"

int main(){
    //TODO Find adequate parameters
    const char *param_str = "type a\nq 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791\nh 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776\n\nr 730750818665451621361119245571504901405976559617\nexp2 159\nexp1 107\nsign1 1\nsign0 1";
    const char *S = "Alice";
    const char *R = "Bob";
    const char *X = "Charlie";
    const char *m = "It works!";
    char *m_dec;
    MKP *mkp;
    EK *ek_S;
    DK *dk_R, *dk_X;
    Cipher *c;
    size_t S_len, R_len, X_len, m_len, m_dec_len;
    int i;

    S_len = strlen(S) + 1;
    R_len = strlen(R) + 1;
    m_len = strlen(m) + 1;
    X_len = strlen(X) + 1;

    if(1 == MKP_init(param_str, &mkp)) {
        clear(mkp, ek_S, dk_R, c, m_dec, dk_X);
        return 1;
    }
    if(1 == setup(&mkp)) {
        clear(mkp, ek_S, dk_R, c, m_dec, dk_X);
        return 1;
    }
    element_printf("mpk:\n%B\n%B\nmsk:\n%B\n%B\n", mkp->mpk->P, mkp->mpk->P0, mkp->msk->r, mkp->msk->s);

    if(1 == EK_init(mkp->mpk->pairing, &ek_S)) {
        clear(mkp, ek_S, dk_R, c, m_dec, dk_X);
        return 1;
    }
    if(1 == sk_gen(mkp, (unsigned char *)S, S_len, &ek_S)) {
        clear(mkp, ek_S, dk_R, c, m_dec, dk_X);
        return 1;
    }
    element_printf("ek of \"%s\":\n%B\n", S, ek_S->k);

    if(1 == DK_init(mkp->mpk->pairing, &dk_R)) {
        clear(mkp, ek_S, dk_R, c, m_dec, dk_X);
        return 1;
    }
    if(1 == rk_gen(mkp, (unsigned char *)R, R_len, &dk_R)) {
        clear(mkp, ek_S, dk_R, c, m_dec, dk_X);
        return 1;
    }
    element_printf("dk of \"%s\":\n%B\n%B\n%B\n", R, dk_R->k1, dk_R->k2, dk_R->k3->h);

    if(1 == Cipher_init(mkp->mpk->pairing, &c)) {
        clear(mkp, ek_S, dk_R, c, m_dec, dk_X);
        return 1;
    }
    if(1 == enc(mkp->mpk, ek_S, (unsigned char *)R, R_len, (unsigned char *)m, m_len, &c)) {
        clear(mkp, ek_S, dk_R, c, m_dec, dk_X);
        return 1;
    }
    element_printf("cipher of \"%s\" from \"%s\" to \"%s\":\n%B\n%B\n", m, S, R, c->T, c->U);
    for(i = 0; i < c->V_len; i++) {
        printf("0x%x", c->V[i]);
    }
    printf("\n");

    m_dec_len = c->V_len;
    if((m_dec = (char *) malloc(m_dec_len * sizeof(char))) == NULL) {
        clear(mkp, ek_S, dk_R, c, m_dec, dk_X);
        return 1;
    }
    if(1 == dec(mkp->mpk, dk_R, (unsigned char *)S, S_len, c, (unsigned char **)&m_dec, &m_dec_len)) {
        clear(mkp, ek_S, dk_R, c, m_dec, dk_X);
        return 1;
    }
    if(m_dec_len == 0) {
        printf("ASSERT ERROR: \"%s\" failed to decrypt the cipher using sender identity \"%s\"\n", R, S);
        clear(mkp, ek_S, dk_R, c, m_dec, dk_X);
        return 1;
    } else {
        printf("\"%s\" successfully decrypted the cipher from \"%s\", retrieved message:\n%s\n", R, S, m_dec);
    }

    if(1 == DK_init(mkp->mpk->pairing, &dk_X)) {
        clear(mkp, ek_S, dk_R, c, m_dec, dk_X);
        return 1;
    }
    if(1 == rk_gen(mkp, (unsigned char *)X, X_len, &dk_X)) {
        clear(mkp, ek_S, dk_R, c, m_dec, dk_X);
        return 1;
    }
    element_printf("dk of \"%s\":\n%B\n%B\n%B\n", X, dk_X->k1, dk_X->k2, dk_X->k3->h);

    m_dec_len = c->V_len;
    if(1 == dec(mkp->mpk, dk_X, (unsigned char *)S, S_len, c, (unsigned char **)&m_dec, &m_dec_len)) {
        clear(mkp, ek_S, dk_R, c, m_dec, dk_X);
        return 1;
    }
    if(m_dec_len == 0) {
        printf("\"%s\" failed to decrypt the cipher using sender identity \"%s\"\n", X, S);
    } else {
        printf("ASSERT ERROR: \"%s\" successfully decrypted the cipher from \"%s\", retrieved message:\n%s\n", X, S, m_dec);
        clear(mkp, ek_S, dk_R, c, m_dec, dk_X);
        return 1;
    }

    m_dec_len = c->V_len;
    if(1 == dec(mkp->mpk, dk_R, (unsigned char *)X, X_len, c, (unsigned char **)&m_dec, &m_dec_len)) {
        clear(mkp, ek_S, dk_R, c, m_dec, dk_X);
        return 1;
    }
    if(m_dec_len != 0) {
        printf("ASSERT ERROR: \"%s\" successfully decrypted the cipher from \"%s\", retrieved message:\n%s\n", R, X, m_dec);
        clear(mkp, ek_S, dk_R, c, m_dec, dk_X);
        return 1;
    } else {
        printf("\"%s\" failed to decrypt the cipher using sender identity \"%s\"\n", R, X);
    }

    clear(mkp, ek_S, dk_R, c, m_dec, dk_X);
    return 0;
}

void clear(MKP *mkp, EK *ek, DK *dk, Cipher *c, char *m_dec, DK *dk_X) {
    DK_clear(dk_X);
    free(m_dec);
    Cipher_clear(c);
    DK_clear(dk);
    EK_clear(ek);
    MKP_clear(mkp);
}