#ifndef IBME_CIPHER_H
#define IBME_CIPHER_H

#include <pbc/pbc.h>

typedef struct _cipher {
    element_t T;
    element_t U;
    unsigned char *V;
    size_t V_len;
} Cipher;

int Cipher_init(pairing_t pairing, Cipher **c);
void Cipher_clear(Cipher *c);
int Cipher_snprint(char *s, size_t n, Cipher *c);
int Cipher_set_str(char *s, size_t n, Cipher *c);

#endif //IBME_CIPHER_H
