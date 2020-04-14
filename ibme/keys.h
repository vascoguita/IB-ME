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
    Hash_G1 *k3;
} DK;

int MPK_init(pbc_param_t param, MPK **mpk);
void MPK_clear(MPK *mpk);

int MSK_init(pairing_t pairing, MSK **msk);
void MSK_clear(MSK *msk);

int MKP_init(const char *param_str, MKP **mkp);
void MKP_clear(MKP *mkp);

int EK_init(pairing_t pairing, EK **ek);
void EK_clear(EK *ek);

int DK_init(pairing_t pairing, DK **dk);
void DK_clear(DK *dk);

#endif //IBME_KEYS_H