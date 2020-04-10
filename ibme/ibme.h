#ifndef IBME_IBME_H
#define IBME_IBME_H

#include <pbc/pbc.h>

#include "keys.h"

void setup(MKP **mkp);
int sk_gen(const MKP *mkp, const char *S, EK **ek);
int rk_gen(const MKP *mkp, const char *R, DK **dk);
void enc();
void dec();

#endif //IBME_IBME_H