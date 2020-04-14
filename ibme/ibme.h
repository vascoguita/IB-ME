#ifndef IBME_IBME_H
#define IBME_IBME_H

#include <pbc/pbc.h>

#include "keys.h"
#include "cipher.h"

int setup(MKP **mkp);
int sk_gen(const MKP *mkp, const unsigned char *S, size_t S_len, EK **ek);
int rk_gen(const MKP *mkp, const unsigned char *R, size_t R_len, DK **dk);
int enc(MPK *mpk, EK *ek, const unsigned char *R, size_t R_len, const unsigned char *m, size_t m_len, Cipher **c);
int dec(MPK *mpk, DK *dk, const unsigned char *S, size_t S_len, Cipher *c, unsigned char **m, size_t *m_len);

#endif //IBME_IBME_H