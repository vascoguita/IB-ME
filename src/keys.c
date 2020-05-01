#include <pbc.h>
#include <string.h>

#include "keys.h"
#include "hash.h"
#include "memory.h"
#include "utils.h"

int MPK_init(pairing_t pairing, MPK **mpk) {
    if((*mpk = (struct _mpk*) ibme_malloc(sizeof(struct _mpk))) == NULL) {
        return 1;
    }

    element_init_G1((*mpk)->P, pairing);
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
        ibme_free(mpk);
    }
}

int MPK_snprint(char *s, size_t n, MPK *mpk) {
    size_t result, left;
    int status;

    result = 0;

    status = snprintf(s, n, "[");
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = element_snprint(s + result, left, mpk->P);
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, ", ");
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = element_snprint(s + result, left, mpk->P0);
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, "]");
    if (status < 0) {
        return status;
    }
    return (int)result + status;
}

int MPK_set_str(char *s, size_t n, MPK *mpk) {
    size_t result, left;
    int status;

    result = 0;

    status = strlen("[");
    if(strncmp(s, "[", status) != 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if((status = element_set_str(mpk->P, s + result, 10)) == 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    status = strlen(", ");
    if(strncmp(s + result, ", ", status) != 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if((status = element_set_str(mpk->P0, s + result, 10)) == 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    status = strlen("]");
    if(strncmp(s + result, "]", status) != 0) {
        return 0;
    }

    return (int)result + status;
}

int MSK_init(pairing_t pairing, MSK **msk) {
    if((*msk = (struct _msk*) ibme_malloc(sizeof(struct _msk))) == NULL) {
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
        ibme_free(msk);
    }
}

int MSK_snprint(char *s, size_t n, MSK *msk) {
    size_t result, left;
    int status;

    result = 0;

    status = snprintf(s, n, "[");
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = element_snprint(s + result, left, msk->r);
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, ", ");
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = element_snprint(s + result, left, msk->s);
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, "]");
    if (status < 0) {
        return status;
    }
    return (int)result + status;
}

int MSK_set_str(char *s, size_t n, MSK *msk) {
    size_t result, left;
    int status;

    result = 0;

    status = strlen("[");
    if(strncmp(s, "[", status) != 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if((status = element_set_str(msk->r, s + result, 10)) == 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    status = strlen(", ");
    if(strncmp(s + result, ", ", status) != 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if((status = element_set_str(msk->s, s + result, 10)) == 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    status = strlen("]");
    if(strncmp(s + result, "]", status) != 0) {
        return 0;
    }

    return (int)result + status;
}

int MKP_init(pairing_t pairing, MKP **mkp) {
    if((*mkp = (struct _mkp*) ibme_malloc(sizeof(struct _mkp))) == NULL) {
        return 1;
    }

    if(1 == MPK_init(pairing, &((*mkp)->mpk))) {
        MKP_clear(*mkp);
        return 1;
    }

    if(1 == MSK_init(pairing, &((*mkp)->msk))) {
        MKP_clear(*mkp);
        return 1;
    }

    return 0;
}

void MKP_clear(MKP *mkp) {
    if(mkp != NULL) {
        MPK_clear(mkp->mpk);
        MSK_clear(mkp->msk);
        ibme_free(mkp);
    }
}

int MKP_snprint(char *s, size_t n, MKP *mkp) {
    size_t result, left;
    int status;

    result = 0;

    status = snprintf(s, n, "[");
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = MPK_snprint(s + result, left, mkp->mpk);
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, ", ");
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = MSK_snprint(s + result, left, mkp->msk);
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, "]");
    if (status < 0) {
        return status;
    }
    return (int)result + status;
}

int MKP_set_str(char *s, size_t n, MKP *mkp) {
    size_t result, left;
    int status;

    result = 0;

    status = strlen("[");
    if(strncmp(s, "[", status) != 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if((status = MPK_set_str(s + result, left, mkp->mpk)) == 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    status = strlen(", ");
    if(strncmp(s + result, ", ", status) != 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if((status = MSK_set_str(s + result, left, mkp->msk)) == 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    status = strlen("]");
    if(strncmp(s + result, "]", status) != 0) {
        return 0;
    }

    return (int)result + status;
}

int EK_init(pairing_t pairing, EK **ek) {
    if((*ek = (struct _ek*) ibme_malloc(sizeof(struct _ek))) == NULL) {
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
        ibme_free(ek);
    }
}

int EK_snprint(char *s, size_t n, EK *ek) {
    size_t result, left;
    int status;

    result = 0;

    status = snprintf(s, n, "[");
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = element_snprint(s + result, left, ek->k);
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, "]");
    if (status < 0) {
        return status;
    }
    return (int)result + status;
}

int EK_set_str(char *s, size_t n, EK *ek) {
    size_t result, left;
    int status;

    result = 0;

    status = strlen("[");
    if(strncmp(s, "[", status) != 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if((status = element_set_str(ek->k, s + result, 10)) == 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    status = strlen("]");
    if(strncmp(s + result, "]", status) != 0) {
        return 0;
    }

    return (int)result + status;
}

int DK_init(pairing_t pairing, DK **dk) {
    if((*dk = (struct _dk*) ibme_malloc(sizeof(struct _dk))) == NULL){
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
        ibme_free(dk);
    }
}

int DK_snprint(char *s, size_t n, DK *dk) {
    size_t result, left;
    int status;

    result = 0;

    status = snprintf(s, n, "[");
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = element_snprint(s + result, left, dk->k1);
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, ", ");
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = element_snprint(s + result, left, dk->k2);
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, ", ");
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = Hash_G1_snprint(s + result, left, dk->k3);
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, "]");
    if (status < 0) {
        return status;
    }
    return (int)result + status;
}

int DK_set_str(char *s, size_t n, DK *dk) {
    size_t result, left;
    int status;

    result = 0;

    status = strlen("[");
    if(strncmp(s, "[", status) != 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if((status = element_set_str(dk->k1, s + result, 10)) == 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    status = strlen(", ");
    if(strncmp(s + result, ", ", status) != 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if((status = element_set_str(dk->k2, s + result, 10)) == 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    status = strlen(", ");
    if(strncmp(s + result, ", ", status) != 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if((status = Hash_G1_set_str(s + result, left, dk->k3)) == 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    status = strlen("]");
    if(strncmp(s + result, "]", status) != 0) {
        return 0;
    }

    return (int)result + status;
}