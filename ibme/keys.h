#ifndef IBME_KEYS_H
#define IBME_KEYS_H

#include <pbc/pbc.h>

#include "hash.h"

typedef struct _mpk {
    pairing_t pairing;
    element_t P;
    element_t P0;
} MPK;

typedef struct _msk {
    element_t r;
    element_t s;
} MSK;

typedef struct _mkp {
    MPK *mpk;
    MSK *msk;
} MKP;

typedef struct _ek {
    element_t k;
} EK;

typedef struct _dk {
    element_t k1;
    element_t k2;
    Hash *k3;
} DK;

MPK *MPK_init(pbc_param_t param);
void MPK_clear(MPK *mpk);

MSK *MSK_init(pairing_t pairing);
void MSK_clear(MSK *msk);

MKP *MKP_init(const char *param_str);
void MKP_clear(MKP *mkp);

EK *EK_init(pairing_t pairing);
void EK_clear(EK *ek);

DK *DK_init(pairing_t pairing);
void DK_clear(DK *dk);

#endif //IBME_KEYS_H