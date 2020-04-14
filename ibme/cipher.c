#include <pbc/pbc.h>

#include "cipher.h"

int Cipher_init(pairing_t pairing, size_t V_len, Cipher ** c) {
    if((*c = (struct _cipher*) malloc(sizeof(struct _cipher))) == NULL) {
        return 1;
    }

    element_init_G1((*c)->T, pairing);
    if(((*c)->T) == NULL) {
        Cipher_clear(*c);
        return 1;
    }

    element_init_G1((*c)->U, pairing);
    if(((*c)->U) == NULL) {
        Cipher_clear(*c);
        return 1;
    }

    if(((*c)->V_len = V_len) < 1) {
        Cipher_clear(*c);
        return 1;
    }

    if(((*c)->V = (unsigned char*) malloc((*c)->V_len * sizeof(unsigned char))) == NULL) {
        Cipher_clear(*c);
        return 1;
    }
    return 0;
}

void Cipher_clear(Cipher *c) {
    free(c->V);
    element_clear(c->U);
    element_clear(c->T);
    free(c);
}