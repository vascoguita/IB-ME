#include <pbc/pbc.h>
#include <string.h>

#include "hash.h"
#include "keys.h"
#include "ibme.h"

void setup(MKP **mkp) {
    element_random((*mkp)->msk->r);
    element_random((*mkp)->msk->s);
    element_random((*mkp)->mpk->P);
    //TODO Find adequate arithmetic operation. It might be element_mul_zn(mpk->P0, P, r) instead
    element_pow_zn((*mkp)->mpk->P0, (*mkp)->mpk->P, (*mkp)->msk->r);

    element_printf("mpk:\n%B\n%B\nmsk:\n%B\n%B\n", (*mkp)->mpk->P, (*mkp)->mpk->P0, (*mkp)->msk->r, (*mkp)->msk->s);
}

int sk_gen(const MKP *mkp, const char *S, EK **ek) {
    Hash *hash = Hash_init(mkp->mpk->pairing);

    if(1 == H_prime((const unsigned char *)S, strlen(S), mkp->mpk->pairing, &hash)) {
        return 1;
    }

    element_pow_zn((*ek)->k, hash->h, mkp->msk->s);

    Hash_clear(hash);

    element_printf("ek of \"%s\":\n%B\n", S, (*ek)->k);

    return 0;
}

int rk_gen(const MKP *mkp, const char *R, DK **dk) {

    if(1 == H((const unsigned char *)R, strlen(R), mkp->mpk->pairing, &((*dk)->k3)) ){
        return 1;
    }

    element_pow_zn((*dk)->k1, (*dk)->k3->h, mkp->msk->r);
    element_pow_zn((*dk)->k2, (*dk)->k3->h, mkp->msk->s);

    element_printf("dk of \"%s\":\n%B\n%B\n%B\n", R, (*dk)->k1, (*dk)->k2, (*dk)->k3->h);

    return 0;
}