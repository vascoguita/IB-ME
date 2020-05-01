#ifndef IBME_IBME_H
#define IBME_IBME_H

#ifndef DEBUG
#define DEBUG 0
#endif

#include <pbc.h>

#include "keys.h"
#include "cipher.h"

int setup(MKP *mkp);
int sk_gen(pairing_t pairing, MSK *msk, const unsigned char *S, size_t S_len, EK *ek);
int rk_gen(MSK *msk, const unsigned char *R, size_t R_len, DK *dk);
int enc(pairing_t pairing, MPK *mpk, EK *ek, const unsigned char *R, size_t R_len, const unsigned char *m, size_t m_len, Cipher *c);
int dec(pairing_t pairing, DK *dk, const unsigned char *S, size_t S_len, Cipher *c, unsigned char *m, size_t *m_len);

#endif //IBME_IBME_H