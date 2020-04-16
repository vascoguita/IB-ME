#include <pbc/pbc.h>

#include "keys.h"
#include "hash.h"

int MPK_init(pbc_param_t param, MPK **mpk){
    if((*mpk = (struct _mpk*) malloc(sizeof(struct _mpk))) == NULL) {
        return 1;
    }

    pairing_init_pbc_param((*mpk)->pairing, param);
    if(((*mpk)->pairing) == NULL) {
        MPK_clear(*mpk);
        return 1;
    }

    element_init_G1((*mpk)->P, (*mpk)->pairing);
    if(((*mpk)->P) == NULL) {
        MPK_clear(*mpk);
        return 1;
    }

    element_init_same_as((*mpk)->P0, (*mpk)->P);
    if(((*mpk)->P0) == NULL) {
        MPK_clear(*mpk);
        return 1;
    }
    return 0;
}

void MPK_clear(MPK *mpk) {
    if(mpk != NULL) {
        element_clear(mpk->P0);
        element_clear(mpk->P);
        pairing_clear(mpk->pairing);
        free(mpk);
    }
}

int MSK_init(pairing_t pairing, MSK **msk) {
    if((*msk = (struct _msk*) malloc(sizeof(struct _msk))) == NULL) {
        return 1;
    }

    element_init_Zr((*msk)->r, pairing);
    if(((*msk)->r) == NULL) {
        MSK_clear(*msk);
        return 1;
    }

    element_init_Zr((*msk)->s, pairing);
    if(((*msk)->s) == NULL) {
        MSK_clear(*msk);
        return 1;
    }
    return 0;
}

void MSK_clear(MSK *msk){
    if(msk != NULL) {
        element_clear(msk->s);
        element_clear(msk->r);
        free(msk);
    }
}

int MKP_init(const char *param_str, MKP **mkp) {
    pbc_param_t param;

    if(1 == pbc_param_init_set_str(param, param_str)) {
        return 1;
    }

    if((*mkp = (struct _mkp*) malloc(sizeof(struct _mkp))) == NULL) {
        pbc_param_clear(param);
        return 1;
    }

    if(1 == MPK_init(param, &((*mkp)->mpk))) {
        pbc_param_clear(param);
        MKP_clear(*mkp);
        return 1;
    }
    pbc_param_clear(param);

    if(1 == MSK_init((*mkp)->mpk->pairing, &((*mkp)->msk))) {
        MKP_clear(*mkp);
        return 1;
    }

    return 0;
}

void MKP_clear(MKP *mkp) {
    if(mkp != NULL) {
        MPK_clear(mkp->mpk);
        MSK_clear(mkp->msk);
        free(mkp);
    }
}

int EK_init(pairing_t pairing, EK **ek) {
    if((*ek = (struct _ek*) malloc(sizeof(struct _ek))) == NULL) {
        return 1;
    }

    element_init_G1((*ek)->k, pairing);
    if(((*ek)->k) == NULL) {
        EK_clear(*ek);
        return 1;
    }
    return 0;
}

void EK_clear(EK *ek) {
    if(ek != NULL) {
        element_clear(ek->k);
        free(ek);
    }
}

int DK_init(pairing_t pairing, DK **dk) {
    if((*dk = (struct _dk*) malloc(sizeof(struct _dk))) == NULL){
        return 1;
    }

    element_init_G1((*dk)->k1, pairing);
    if(((*dk)->k1) == NULL) {
        DK_clear(*dk);
        return 1;
    }

    element_init_G1((*dk)->k2, pairing);
    if(((*dk)->k2) == NULL) {
        DK_clear(*dk);
        return 1;
    }

    if(1 == Hash_G1_init(pairing, &((*dk)->k3))) {
        DK_clear(*dk);
        return 1;
    }
    return 0;
}

void DK_clear(DK *dk) {
    if(dk != NULL) {
        Hash_G1_clear(dk->k3);
        element_clear(dk->k2);
        element_clear(dk->k1);
        free(dk);
    }
}