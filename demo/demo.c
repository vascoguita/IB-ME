#include <ibme.h>
#include <string.h>
#include "demo.h"

int main(){
    const char *S = "Alice";
    const char *R = "Bob";
    const char *X = "Charlie";
    const char *m = "It works!";
    char *m_dec = NULL;
    MKP *mkp = NULL;
    EK *ek_S = NULL;
    DK *dk_R = NULL;
    DK *dk_X = NULL;
    Cipher *c = NULL;
    size_t S_len, R_len, X_len, m_len, m_dec_len;

    S_len = strlen(S) + 1;
    R_len = strlen(R) + 1;
    m_len = strlen(m) + 1;
    X_len = strlen(X) + 1;

    if(1 == MKP_init(&mkp)) {
        clear(mkp, ek_S, dk_R, c, m_dec, dk_X);
        return 1;
    }
    if(1 == setup(&mkp)) {
        clear(mkp, ek_S, dk_R, c, m_dec, dk_X);
        return 1;
    }

    if(1 == EK_init(mkp->mpk->pairing, &ek_S)) {
        clear(mkp, ek_S, dk_R, c, m_dec, dk_X);
        return 1;
    }
    if(1 == sk_gen(mkp, (unsigned char *)S, S_len, &ek_S)) {
        clear(mkp, ek_S, dk_R, c, m_dec, dk_X);
        return 1;
    }

    if(1 == DK_init(mkp->mpk->pairing, &dk_R)) {
        clear(mkp, ek_S, dk_R, c, m_dec, dk_X);
        return 1;
    }
    if(1 == rk_gen(mkp, (unsigned char *)R, R_len, &dk_R)) {
        clear(mkp, ek_S, dk_R, c, m_dec, dk_X);
        return 1;
    }

    if(1 == Cipher_init(mkp->mpk->pairing, &c)) {
        clear(mkp, ek_S, dk_R, c, m_dec, dk_X);
        return 1;
    }
    if(1 == enc(mkp->mpk, ek_S, (unsigned char *)R, R_len, (unsigned char *)m, m_len, &c)) {
        clear(mkp, ek_S, dk_R, c, m_dec, dk_X);
        return 1;
    }

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