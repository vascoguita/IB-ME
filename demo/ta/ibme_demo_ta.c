#include <tee_internal_api.h>
#include <ibme/ibme.h>
#include <string.h>

#include <ibme_demo_ta.h>

static char *param_str = (char *) "type a\nq 87807107996633125224377819847540498158068831994142082110286533992664756308"
                                  "80222957078625179422662221423155858769582317459277713367317481324925129998224791\nh "
                                  "120160122648911460793888213667405342048029544012513118229196151310472072893597045311"
                                  "02844802183906537786776\nr 730750818665451621361119245571504901405976559617\nexp2 15"
                                  "9\nexp1 107\nsign1 1\nsign0 1";

TEE_Result TA_CreateEntryPoint(void) {
    const char *S = "Alice";
    const char *R = "Bob";
    const char *X = "Charlie";
    const char *m = "It works!";
    char *m_dec;

    size_t S_size, R_size, X_size, m_size, m_dec_size;

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
    int tmp_len;

    S_size = strlen(S) + 1;
    R_size = strlen(R) + 1;
    m_size = strlen(m) + 1;
    X_size = strlen(X) + 1;

    if(1 == pairing_init_set_str(pairing, param_str)) {
        return TEE_ERROR_GENERIC;
    }

    if(!(mkp = MKP_init(pairing))) {
        pairing_clear(pairing);
        return TEE_ERROR_GENERIC;
    }
    if(1 == ibme_setup(mkp)) {
        MKP_clear(mkp);
        pairing_clear(pairing);
        return TEE_ERROR_GENERIC;
    }

    if(!(ek_S = EK_init(pairing))) {
        MKP_clear(mkp);
        pairing_clear(pairing);
        return TEE_ERROR_GENERIC;
    }
    if(1 == ibme_sk_gen(pairing, mkp->msk, (unsigned char *)S, S_size, ek_S)) {
        EK_clear(ek_S);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return TEE_ERROR_GENERIC;
    }

    if(!(dk_R = DK_init(pairing))) {
        EK_clear(ek_S);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return TEE_ERROR_GENERIC;
    }
    if(1 == ibme_rk_gen(mkp->msk, (unsigned char *)R, R_size, dk_R)) {
        DK_clear(dk_R);
        EK_clear(ek_S);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return TEE_ERROR_GENERIC;
    }

    if(!(dk_X = DK_init(pairing))) {
        DK_clear(dk_R);
        EK_clear(ek_S);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return TEE_ERROR_GENERIC;
    }
    if(1 == ibme_rk_gen(mkp->msk, (unsigned char *)X, X_size, dk_X)) {
        DK_clear(dk_X);
        DK_clear(dk_R);
        EK_clear(ek_S);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return TEE_ERROR_GENERIC;
    }

    if((tmp_len = MPK_snprint(NULL, 0, mkp->mpk)) < 0) {
        DK_clear(dk_X);
        DK_clear(dk_R);
        EK_clear(ek_S);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return TEE_ERROR_GENERIC;
    }
    mpk_str_len = (size_t)tmp_len;
    if((mpk_str = (char *) malloc((mpk_str_len + 1) * sizeof(char))) == NULL) {
        DK_clear(dk_X);
        DK_clear(dk_R);
        EK_clear(ek_S);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return TEE_ERROR_GENERIC;
    }
    if(tmp_len != MPK_snprint(mpk_str, (mpk_str_len + 1) , mkp->mpk)) {
        free(mpk_str);
        DK_clear(dk_X);
        DK_clear(dk_R);
        EK_clear(ek_S);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return TEE_ERROR_GENERIC;
    }
    MPK_clear(mkp->mpk);
    if(!(mkp->mpk = MPK_init(pairing))) {
        free(mpk_str);
        DK_clear(dk_X);
        DK_clear(dk_R);
        EK_clear(ek_S);
        pairing_clear(pairing);
        return TEE_ERROR_GENERIC;
    }
    if(0 == MPK_set_str(mpk_str, mpk_str_len, mkp->mpk)) {
        free(mpk_str);
        DK_clear(dk_X);
        DK_clear(dk_R);
        EK_clear(ek_S);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return TEE_ERROR_GENERIC;
    }
    free(mpk_str);

    if((tmp_len = EK_snprint(NULL, 0, ek_S)) < 0) {
        DK_clear(dk_X);
        DK_clear(dk_R);
        EK_clear(ek_S);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return TEE_ERROR_GENERIC;
    }
    ek_S_str_len = (size_t)tmp_len;
    if((ek_S_str = (char *) malloc((ek_S_str_len + 1) * sizeof(char))) == NULL) {
        DK_clear(dk_X);
        DK_clear(dk_R);
        EK_clear(ek_S);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return TEE_ERROR_GENERIC;
    }
    if(tmp_len != EK_snprint(ek_S_str, (ek_S_str_len + 1) , ek_S)) {
        free(ek_S_str);
        DK_clear(dk_X);
        DK_clear(dk_R);
        EK_clear(ek_S);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return TEE_ERROR_GENERIC;
    }
    EK_clear(ek_S);
    if(!(ek_S = EK_init(pairing))) {
        free(ek_S_str);
        DK_clear(dk_X);
        DK_clear(dk_R);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return TEE_ERROR_GENERIC;
    }
    if(0 == EK_set_str(ek_S_str, ek_S_str_len, ek_S)) {
        free(ek_S_str);
        DK_clear(dk_X);
        DK_clear(dk_R);
        EK_clear(ek_S);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return TEE_ERROR_GENERIC;
    }
    free(ek_S_str);

    if((tmp_len = DK_snprint(NULL, 0, dk_R)) < 0) {
        DK_clear(dk_X);
        DK_clear(dk_R);
        EK_clear(ek_S);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return TEE_ERROR_GENERIC;
    }
    dk_R_str_len = (size_t)tmp_len;
    if((dk_R_str = (char *) malloc((dk_R_str_len + 1) * sizeof(char))) == NULL) {
        DK_clear(dk_X);
        DK_clear(dk_R);
        EK_clear(ek_S);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return TEE_ERROR_GENERIC;
    }
    if(tmp_len != DK_snprint(dk_R_str, (dk_R_str_len + 1) , dk_R)) {
        free(ek_S_str);
        DK_clear(dk_X);
        DK_clear(dk_R);
        EK_clear(ek_S);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return TEE_ERROR_GENERIC;
    }
    DK_clear(dk_R);
    if(!(dk_R = DK_init(pairing))) {
        free(ek_S_str);
        DK_clear(dk_X);
        EK_clear(ek_S);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return TEE_ERROR_GENERIC;
    }
    if(0 == DK_set_str(dk_R_str, dk_R_str_len, dk_R)) {
        free(ek_S_str);
        DK_clear(dk_X);
        DK_clear(dk_R);
        EK_clear(ek_S);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return TEE_ERROR_GENERIC;
    }
    free(dk_R_str);

    if(!(c = Cipher_init(pairing))) {
        DK_clear(dk_X);
        DK_clear(dk_R);
        EK_clear(ek_S);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return TEE_ERROR_GENERIC;
    }
    if(1 == ibme_enc(pairing, mkp->mpk, ek_S, (unsigned char *)R, R_size, (unsigned char *)m, m_size, c)) {
        Cipher_clear(c);
        DK_clear(dk_X);
        DK_clear(dk_R);
        EK_clear(ek_S);
        MKP_clear(mkp);
        pairing_clear(pairing);
        return TEE_ERROR_GENERIC;
    } else {
        IMSG("\"%s\" encrypted message \"%s\" using receiver identity \"%s\".\n", S, m, R);
    }
    MKP_clear(mkp);
    EK_clear(ek_S);

    if((tmp_len = Cipher_snprint(NULL, 0, c)) < 0) {
        Cipher_clear(c);
        DK_clear(dk_X);
        DK_clear(dk_R);
        pairing_clear(pairing);
        return TEE_ERROR_GENERIC;
    }
    c_str_len = (size_t)tmp_len;
    if((c_str = (char *) malloc((c_str_len + 1) * sizeof(char))) == NULL) {
        Cipher_clear(c);
        DK_clear(dk_X);
        DK_clear(dk_R);
        pairing_clear(pairing);
        return TEE_ERROR_GENERIC;
    }
    if(tmp_len != Cipher_snprint(c_str, (c_str_len + 1) , c)) {
        free(c_str);
        Cipher_clear(c);
        DK_clear(dk_X);
        DK_clear(dk_R);
        pairing_clear(pairing);
        return TEE_ERROR_GENERIC;
    }
    Cipher_clear(c);
    if(!(c = Cipher_init(pairing))) {
        free(c_str);
        DK_clear(dk_X);
        DK_clear(dk_R);
        pairing_clear(pairing);
        return TEE_ERROR_GENERIC;
    }
    if(0 == Cipher_set_str(c_str, c_str_len, c)) {
        free(c_str);
        Cipher_clear(c);
        DK_clear(dk_X);
        DK_clear(dk_R);
        pairing_clear(pairing);
        return TEE_ERROR_GENERIC;
    }
    free(c_str);

    m_dec_size = 0;
    if(1 == ibme_dec(pairing, dk_R, (unsigned char *)S, S_size, c, NULL, &m_dec_size)) {
        Cipher_clear(c);
        DK_clear(dk_X);
        DK_clear(dk_R);
        pairing_clear(pairing);
        return TEE_ERROR_GENERIC;
    }
    if((m_dec = (char *) malloc(m_dec_size * sizeof(char))) == NULL) {
        Cipher_clear(c);
        DK_clear(dk_X);
        DK_clear(dk_R);
        pairing_clear(pairing);
        return TEE_ERROR_GENERIC;
    }
    if(1 == ibme_dec(pairing, dk_R, (unsigned char *)S, S_size, c, (unsigned char *)m_dec, &m_dec_size)) {
        IMSG("ASSERT ERROR: \"%s\" failed to decrypt the cipher using sender identity \"%s\".\n", R, S);
        free(m_dec);
        Cipher_clear(c);
        DK_clear(dk_X);
        DK_clear(dk_R);
        pairing_clear(pairing);
        return TEE_ERROR_GENERIC;
    } else {
        IMSG("\"%s\" successfully decrypted the cipher using sender identity \"%s\".\nRetrieved message:\"%s\".\n", R, S, m_dec);
    }

    if(1 == ibme_dec(pairing, dk_X, (unsigned char *)S, S_size, c, (unsigned char *)m_dec, &m_dec_size)) {
        IMSG("\"%s\" failed to decrypt the cipher using sender identity \"%s\".\n", X, S);
    } else {
        IMSG("ASSERT ERROR: \"%s\" successfully decrypted the cipher using sender identity \"%s\".\nRetrieved message:\"%s\".\n", X, S, m_dec);
        free(m_dec);
        Cipher_clear(c);
        DK_clear(dk_X);
        DK_clear(dk_R);
        pairing_clear(pairing);
        return TEE_ERROR_GENERIC;
    }
    DK_clear(dk_X);

    if(1 == ibme_dec(pairing, dk_R, (unsigned char *)X, X_size, c, (unsigned char *)m_dec, &m_dec_size)) {
        IMSG("\"%s\" failed to decrypt the cipher using sender identity \"%s\".\n", R, X);
    } else {
        IMSG("ASSERT ERROR: \"%s\" successfully decrypted the cipher using sender identity \"%s\".\nRetrieved message:\"%s\".\n", R, X, m_dec);
        free(m_dec);
        Cipher_clear(c);
        DK_clear(dk_R);
        pairing_clear(pairing);
        return TEE_ERROR_GENERIC;
    }

    free(m_dec);
    Cipher_clear(c);
    DK_clear(dk_R);
    pairing_clear(pairing);

    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void) {
    DMSG("has been called");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types, TEE_Param params[4], void **sess_ctx) {
    uint32_t exp_param_types;
    
    (void)&params;
	(void)&sess_ctx;
    
    DMSG("has been called");

    exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
                                        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
	if(param_types != exp_param_types) {
		return TEE_ERROR_BAD_PARAMETERS;
    }

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx) {
    (void)&sess_ctx;

    DMSG("has been called");
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd, uint32_t param_types, TEE_Param params[4]) {
    (void)&sess_ctx;
    (void)&params;
    (void)param_types;

    switch(cmd) {
        default:
            return TEE_ERROR_NOT_SUPPORTED;
    }
}