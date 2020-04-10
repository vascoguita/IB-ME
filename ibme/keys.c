#include "keys.h"
#include "hash.h"

MPK *MPK_init(pbc_param_t param){
    MPK *mpk;

    mpk = (struct _mpk*) malloc(sizeof(struct _mpk));
    pairing_init_pbc_param(mpk->pairing, param);
    element_init_G1(mpk->P, mpk->pairing);
    element_init_same_as(mpk->P0, mpk->P);

    return mpk;
}

void MPK_clear(MPK *mpk) {
    element_clear(mpk->P0);
    element_clear(mpk->P);
    pairing_clear(mpk->pairing);
    free(mpk);
}

MSK *MSK_init(pairing_t pairing){
    MSK *msk;

    msk = (struct _msk*) malloc(sizeof(struct _msk));
    element_init_Zr(msk->r, pairing);
    element_init_Zr(msk->s, pairing);

    return msk;
}

void MSK_clear(MSK *msk){
    element_clear(msk->s);
    element_clear(msk->r);
    free(msk);
}

MKP *MKP_init(const char *param_str) {
    MKP *mkp;
    pbc_param_t param;

    if(pbc_param_init_set_str(param, param_str)) {
        return NULL;
    }

    mkp = (struct _mkp*) malloc(sizeof(struct _mkp));

    mkp->mpk = MPK_init(param);
    pbc_param_clear(param);

    mkp->msk = MSK_init(mkp->mpk->pairing);

    return mkp;
}

void MKP_clear(MKP *mkp) {
    MPK_clear(mkp->mpk);
    MSK_clear(mkp->msk);
    free(mkp);
}

EK *EK_init(pairing_t pairing) {
    EK *ek;
    ek = (struct _ek*) malloc(sizeof(struct _ek));
    element_init_G1(ek->k, pairing);
    return ek;
}

void EK_clear(EK *ek) {
    element_clear(ek->k);
    free(ek);
}

DK *DK_init(pairing_t pairing) {
    DK *dk;
    dk = (struct _dk*) malloc(sizeof(struct _dk));
    element_init_G1(dk->k1, pairing);
    element_init_G1(dk->k2, pairing);
    dk->k3 = Hash_init(pairing);
    return dk;
}

void DK_clear(DK *dk) {
    Hash_clear(dk->k3);
    element_clear(dk->k2);
    element_clear(dk->k1);
    free(dk);
}