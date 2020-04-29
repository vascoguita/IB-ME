#include <ibme.h>
#include <string.h>
#include "demo.h"

int main(){
    const char *S = "Alice";
    const char *R = "Bob";
    const char *X = "Charlie";
    const char *m = "It works!";
    char *m_dec;

    size_t S_len, R_len, X_len, m_len, m_dec_len;

    pairing_t pairing;
    MKP *mkp;
    EK *ek_S;
    DK *dk_R;
    DK *dk_X;
    Cipher *c;

    char *mpk_str;
    char *ek_S_str;
    char *dk_R_str;
    char *c_str;

    size_t mpk_str_len, ek_S_str_len, dk_R_str_len, c_str_len;

    S_len = strlen(S) + 1;
    R_len = strlen(R) + 1;
    m_len = strlen(m) + 1;
    X_len = strlen(X) + 1;

    if(1 == pairing_init_set_str(pairing, param_str)) {
        return 1;
    }

    if(1 == MKP_init(pairing, &mkp)) {
        pairing_clear(pairing);
        return 1;
    }
    if(1 == setup(mkp)) {
        MKP_clear(mkp);
        pairing_clear(pairing);
        return 1;
    }

    if(1 == EK_init(pairing, &ek_S)) {
        MKP_clear(mkp);
        pairing_clear(pairing);
        return 1;
    }
    if(1 == sk_gen(pairing, mkp->msk, (unsigned char *)S, S_len, ek_S)) {
        EK_clear(ek_S);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return 1;
    }

    if(1 == DK_init(pairing, &dk_R)) {
        EK_clear(ek_S);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return 1;
    }
    if(1 == rk_gen(mkp->msk, (unsigned char *)R, R_len, dk_R)) {
        DK_clear(dk_R);
        EK_clear(ek_S);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return 1;
    }

    if(1 == DK_init(pairing, &dk_X)) {
        DK_clear(dk_R);
        EK_clear(ek_S);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return 1;
    }
    if(1 == rk_gen(mkp->msk, (unsigned char *)X, X_len, dk_X)) {
        DK_clear(dk_X);
        DK_clear(dk_R);
        EK_clear(ek_S);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return 1;
    }

    if((mpk_str_len = MPK_snprint(NULL, 0, mkp->mpk)) < 0) {
        DK_clear(dk_X);
        DK_clear(dk_R);
        EK_clear(ek_S);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return 1;
    }
    if((mpk_str = (char *) malloc((mpk_str_len + 1) * sizeof(char))) == NULL) {
        DK_clear(dk_X);
        DK_clear(dk_R);
        EK_clear(ek_S);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return 1;
    }
    if(mpk_str_len != MPK_snprint(mpk_str, (mpk_str_len + 1) , mkp->mpk)) {
        free(mpk_str);
        DK_clear(dk_X);
        DK_clear(dk_R);
        EK_clear(ek_S);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return 1;
    }
    MPK_clear(mkp->mpk);
    if(1 == MPK_init(pairing, &(mkp->mpk))) {
        free(mpk_str);
        DK_clear(dk_X);
        DK_clear(dk_R);
        EK_clear(ek_S);
        pairing_clear(pairing);
        return 1;
    }
    if(0 == MPK_set_str(mpk_str, mpk_str_len, mkp->mpk)) {
        free(mpk_str);
        DK_clear(dk_X);
        DK_clear(dk_R);
        EK_clear(ek_S);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return 1;
    }
    free(mpk_str);

    if((ek_S_str_len = EK_snprint(NULL, 0, ek_S)) < 0) {
        DK_clear(dk_X);
        DK_clear(dk_R);
        EK_clear(ek_S);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return 1;
    }
    if((ek_S_str = (char *) malloc((ek_S_str_len + 1) * sizeof(char))) == NULL) {
        DK_clear(dk_X);
        DK_clear(dk_R);
        EK_clear(ek_S);
        MKP_clear(mkp);
        pairing_clear(pairing);
    }
    if(ek_S_str_len != EK_snprint(ek_S_str, (ek_S_str_len + 1) , ek_S)) {
        free(ek_S_str);
        DK_clear(dk_X);
        DK_clear(dk_R);
        EK_clear(ek_S);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return 1;
    }
    EK_clear(ek_S);
    if(1 == EK_init(pairing, &ek_S)) {
        free(ek_S_str);
        DK_clear(dk_X);
        DK_clear(dk_R);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return 1;
    }
    if(0 == EK_set_str(ek_S_str, ek_S_str_len, ek_S)) {
        free(ek_S_str);
        DK_clear(dk_X);
        DK_clear(dk_R);
        EK_clear(ek_S);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return 1;
    }
    free(ek_S_str);

    if((dk_R_str_len = DK_snprint(NULL, 0, dk_R)) < 0) {
        DK_clear(dk_X);
        DK_clear(dk_R);
        EK_clear(ek_S);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return 1;
    }
    if((dk_R_str = (char *) malloc((dk_R_str_len + 1) * sizeof(char))) == NULL) {
        DK_clear(dk_X);
        DK_clear(dk_R);
        EK_clear(ek_S);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return 1;
    }
    if(dk_R_str_len != DK_snprint(dk_R_str, (dk_R_str_len + 1) , dk_R)) {
        free(ek_S_str);
        DK_clear(dk_X);
        DK_clear(dk_R);
        EK_clear(ek_S);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return 1;
    }
    DK_clear(dk_R);
    if(1 == DK_init(pairing, &dk_R)) {
        free(ek_S_str);
        DK_clear(dk_X);
        EK_clear(ek_S);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return 1;
    }
    if(0 == DK_set_str(dk_R_str, dk_R_str_len, dk_R)) {
        free(ek_S_str);
        DK_clear(dk_X);
        DK_clear(dk_R);
        EK_clear(ek_S);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return 1;
    }
    free(dk_R_str);

    if(1 == Cipher_init(pairing, &c)) {
        DK_clear(dk_X);
        DK_clear(dk_R);
        EK_clear(ek_S);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return 1;
    }
    if(1 == enc(pairing, mkp->mpk, ek_S, (unsigned char *)R, R_len, (unsigned char *)m, m_len, c)) {
        Cipher_clear(c);
        DK_clear(dk_X);
        DK_clear(dk_R);
        EK_clear(ek_S);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return 1;
    } else {
        printf("\"%s\" encrypted message \"%s\" using receiver identity \"%s\"\n", S, m, R);
    }
    MKP_clear(mkp);
    EK_clear(ek_S);

    if((c_str_len = Cipher_snprint(NULL, 0, c)) < 0) {
        Cipher_clear(c);
        DK_clear(dk_X);
        DK_clear(dk_R);
        pairing_clear(pairing);
        return 1;
    }
    if((c_str = (char *) malloc((c_str_len + 1) * sizeof(char))) == NULL) {
        Cipher_clear(c);
        DK_clear(dk_X);
        DK_clear(dk_R);
        pairing_clear(pairing);
        return 1;
    }
    if(c_str_len != Cipher_snprint(c_str, (c_str_len + 1) , c)) {
        free(c_str);
        Cipher_clear(c);
        DK_clear(dk_X);
        DK_clear(dk_R);
        pairing_clear(pairing);
        return 1;
    }
    Cipher_clear(c);
    if(1 == Cipher_init(pairing, &c)) {
        free(c_str);
        DK_clear(dk_X);
        DK_clear(dk_R);
        pairing_clear(pairing);
        return 1;
    }
    if(0 == Cipher_set_str(c_str, c_str_len, c)) {
        free(c_str);
        Cipher_clear(c);
        DK_clear(dk_X);
        DK_clear(dk_R);
        pairing_clear(pairing);
        return 1;
    }
    free(c_str);

    m_dec_len = c->V_len;
    if((m_dec = (char *) malloc(m_dec_len * sizeof(char))) == NULL) {
        Cipher_clear(c);
        DK_clear(dk_X);
        DK_clear(dk_R);
        pairing_clear(pairing);
        return 1;
    }
    if(1 == dec(pairing, dk_R, (unsigned char *)S, S_len, c, (unsigned char *)m_dec, &m_dec_len)) {
        free(m_dec);
        Cipher_clear(c);
        DK_clear(dk_X);
        DK_clear(dk_R);
        pairing_clear(pairing);
        return 1;
    }
    if(m_dec_len == 0) {
        printf("ASSERT ERROR: \"%s\" failed to decrypt the cipher using sender identity \"%s\"\n", R, S);
        free(m_dec);
        Cipher_clear(c);
        DK_clear(dk_X);
        DK_clear(dk_R);
        pairing_clear(pairing);
        return 1;
    } else {
        printf("\"%s\" successfully decrypted the cipher from \"%s\", retrieved message:\n%s\n", R, S, m_dec);
    }

    m_dec_len = c->V_len;
    if(1 == dec(pairing, dk_X, (unsigned char *)S, S_len, c, (unsigned char *)m_dec, &m_dec_len)) {
        free(m_dec);
        Cipher_clear(c);
        DK_clear(dk_X);
        DK_clear(dk_R);
        pairing_clear(pairing);
        return 1;
    }
    if(m_dec_len == 0) {
        printf("\"%s\" failed to decrypt the cipher using sender identity \"%s\"\n", X, S);
    } else {
        printf("ASSERT ERROR: \"%s\" successfully decrypted the cipher from \"%s\", retrieved message:\n%s\n", X, S, m_dec);
        free(m_dec);
        Cipher_clear(c);
        DK_clear(dk_X);
        DK_clear(dk_R);
        pairing_clear(pairing);
        return 1;
    }
    DK_clear(dk_X);

    m_dec_len = c->V_len;
    if(1 == dec(pairing, dk_R, (unsigned char *)X, X_len, c, (unsigned char *)m_dec, &m_dec_len)) {
        free(m_dec);
        Cipher_clear(c);
        DK_clear(dk_R);
        pairing_clear(pairing);
        return 1;
    }
    if(m_dec_len != 0) {
        printf("ASSERT ERROR: \"%s\" successfully decrypted the cipher from \"%s\", retrieved message:\n%s\n", R, X, m_dec);
        free(m_dec);
        Cipher_clear(c);
        DK_clear(dk_R);
        pairing_clear(pairing);
        return 1;
    } else {
        printf("\"%s\" failed to decrypt the cipher using sender identity \"%s\"\n", R, X);
    }

    free(m_dec);
    Cipher_clear(c);
    DK_clear(dk_R);
    pairing_clear(pairing);
    return 0;
}