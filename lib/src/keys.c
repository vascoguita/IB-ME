#include <pbc/pbc.h>
#include <string.h>
#include <stdlib.h>

#include "keys.h"
#include "hash.h"
#include "utils.h"

MPK *MPK_init(pairing_t pairing)
{
    MPK *mpk;
    if (!(mpk = (struct _mpk *)malloc(sizeof(struct _mpk))))
    {
        return NULL;
    }

    element_init_G1(mpk->P, pairing);
    if (!(mpk->P))
    {
        MPK_clear(mpk);
        return NULL;
    }

    element_init_same_as(mpk->P0, mpk->P);
    if (!(mpk->P0))
    {
        MPK_clear(mpk);
        return NULL;
    }
    return mpk;
}

void MPK_clear(MPK *mpk)
{
    if (!mpk)
    {
        element_clear(mpk->P0);
        element_clear(mpk->P);
        free(mpk);
    }
}

int MPK_snprint(char *s, size_t n, MPK *mpk)
{
    size_t result, left;
    int status;

    result = 0;

    status = snprintf(s, n, "[");
    if (status < 0)
    {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = element_snprint(s + result, left, mpk->P);
    if (status < 0)
    {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, ", ");
    if (status < 0)
    {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = element_snprint(s + result, left, mpk->P0);
    if (status < 0)
    {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, "]");
    if (status < 0)
    {
        return status;
    }
    return (int)result + status;
}

int MPK_set_str(char *s, size_t n, MPK *mpk)
{
    size_t result, left;
    int status;

    result = 0;

    status = strlen("[");
    if (strncmp(s, "[", status) != 0)
    {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if ((status = element_set_str(mpk->P, s + result, 10)) == 0)
    {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    status = strlen(", ");
    if (strncmp(s + result, ", ", status) != 0)
    {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if ((status = element_set_str(mpk->P0, s + result, 10)) == 0)
    {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    status = strlen("]");
    if (strncmp(s + result, "]", status) != 0)
    {
        return 0;
    }

    return (int)result + status;
}

MSK *MSK_init(pairing_t pairing)
{
    MSK *msk;
    if (!(msk = (struct _msk *)malloc(sizeof(struct _msk))))
    {
        return NULL;
    }

    element_init_Zr(msk->r, pairing);
    if (!(msk->r))
    {
        MSK_clear(msk);
        return NULL;
    }

    element_init_Zr(msk->s, pairing);
    if (!(msk->s))
    {
        MSK_clear(msk);
        return NULL;
    }
    return msk;
}

void MSK_clear(MSK *msk)
{
    if (!msk)
    {
        element_clear(msk->s);
        element_clear(msk->r);
        free(msk);
    }
}

int MSK_snprint(char *s, size_t n, MSK *msk)
{
    size_t result, left;
    int status;

    result = 0;

    status = snprintf(s, n, "[");
    if (status < 0)
    {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = element_snprint(s + result, left, msk->r);
    if (status < 0)
    {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, ", ");
    if (status < 0)
    {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = element_snprint(s + result, left, msk->s);
    if (status < 0)
    {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, "]");
    if (status < 0)
    {
        return status;
    }
    return (int)result + status;
}

int MSK_set_str(char *s, size_t n, MSK *msk)
{
    size_t result, left;
    int status;

    result = 0;

    status = strlen("[");
    if (strncmp(s, "[", status) != 0)
    {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if ((status = element_set_str(msk->r, s + result, 10)) == 0)
    {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    status = strlen(", ");
    if (strncmp(s + result, ", ", status) != 0)
    {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if ((status = element_set_str(msk->s, s + result, 10)) == 0)
    {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    status = strlen("]");
    if (strncmp(s + result, "]", status) != 0)
    {
        return 0;
    }

    return (int)result + status;
}

MKP *MKP_init(pairing_t pairing)
{
    MKP *mkp;
    if (!(mkp = (struct _mkp *)malloc(sizeof(struct _mkp))))
    {
        return NULL;
    }

    if (!(mkp->mpk = MPK_init(pairing)))
    {
        MKP_clear(mkp);
        return NULL;
    }

    if (!(mkp->msk = MSK_init(pairing)))
    {
        MKP_clear(mkp);
        return NULL;
    }

    return mkp;
}

void MKP_clear(MKP *mkp)
{
    if (!mkp)
    {
        MPK_clear(mkp->mpk);
        MSK_clear(mkp->msk);
        free(mkp);
    }
}

int MKP_snprint(char *s, size_t n, MKP *mkp)
{
    size_t result, left;
    int status;

    result = 0;

    status = snprintf(s, n, "[");
    if (status < 0)
    {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = MPK_snprint(s + result, left, mkp->mpk);
    if (status < 0)
    {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, ", ");
    if (status < 0)
    {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = MSK_snprint(s + result, left, mkp->msk);
    if (status < 0)
    {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, "]");
    if (status < 0)
    {
        return status;
    }
    return (int)result + status;
}

int MKP_set_str(char *s, size_t n, MKP *mkp)
{
    size_t result, left;
    int status;

    result = 0;

    status = strlen("[");
    if (strncmp(s, "[", status) != 0)
    {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if ((status = MPK_set_str(s + result, left, mkp->mpk)) == 0)
    {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    status = strlen(", ");
    if (strncmp(s + result, ", ", status) != 0)
    {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if ((status = MSK_set_str(s + result, left, mkp->msk)) == 0)
    {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    status = strlen("]");
    if (strncmp(s + result, "]", status) != 0)
    {
        return 0;
    }

    return (int)result + status;
}

EK *EK_init(pairing_t pairing)
{
    EK *ek;
    if (!(ek = (struct _ek *)malloc(sizeof(struct _ek))))
    {
        return NULL;
    }

    element_init_G1(ek->k, pairing);
    if (!(ek->k))
    {
        EK_clear(ek);
        return NULL;
    }
    return ek;
}

void EK_clear(EK *ek)
{
    if (!ek)
    {
        element_clear(ek->k);
        free(ek);
    }
}

int EK_snprint(char *s, size_t n, EK *ek)
{
    size_t result, left;
    int status;

    result = 0;

    status = snprintf(s, n, "[");
    if (status < 0)
    {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = element_snprint(s + result, left, ek->k);
    if (status < 0)
    {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, "]");
    if (status < 0)
    {
        return status;
    }
    return (int)result + status;
}

int EK_set_str(char *s, size_t n, EK *ek)
{
    size_t result, left;
    int status;

    result = 0;

    status = strlen("[");
    if (strncmp(s, "[", status) != 0)
    {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if ((status = element_set_str(ek->k, s + result, 10)) == 0)
    {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    status = strlen("]");
    if (strncmp(s + result, "]", status) != 0)
    {
        return 0;
    }

    return (int)result + status;
}

DK *DK_init(pairing_t pairing)
{
    DK *dk;
    if (!(dk = (struct _dk *)malloc(sizeof(struct _dk))))
    {
        return NULL;
    }

    element_init_G1(dk->k1, pairing);
    if (!(dk->k1))
    {
        DK_clear(dk);
        return NULL;
    }

    element_init_G1(dk->k2, pairing);
    if (!(dk->k2))
    {
        DK_clear(dk);
        return NULL;
    }

    if (!(dk->k3 = Hash_G1_init(pairing)))
    {
        DK_clear(dk);
        return NULL;
    }
    return dk;
}

void DK_clear(DK *dk)
{
    if (!dk)
    {
        Hash_G1_clear(dk->k3);
        element_clear(dk->k2);
        element_clear(dk->k1);
        free(dk);
    }
}

int DK_snprint(char *s, size_t n, DK *dk)
{
    size_t result, left;
    int status;

    result = 0;

    status = snprintf(s, n, "[");
    if (status < 0)
    {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = element_snprint(s + result, left, dk->k1);
    if (status < 0)
    {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, ", ");
    if (status < 0)
    {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = element_snprint(s + result, left, dk->k2);
    if (status < 0)
    {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, ", ");
    if (status < 0)
    {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = Hash_G1_snprint(s + result, left, dk->k3);
    if (status < 0)
    {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, "]");
    if (status < 0)
    {
        return status;
    }
    return (int)result + status;
}

int DK_set_str(char *s, size_t n, DK *dk)
{
    size_t result, left;
    int status;

    result = 0;

    status = strlen("[");
    if (strncmp(s, "[", status) != 0)
    {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if ((status = element_set_str(dk->k1, s + result, 10)) == 0)
    {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    status = strlen(", ");
    if (strncmp(s + result, ", ", status) != 0)
    {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if ((status = element_set_str(dk->k2, s + result, 10)) == 0)
    {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    status = strlen(", ");
    if (strncmp(s + result, ", ", status) != 0)
    {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if ((status = Hash_G1_set_str(s + result, left, dk->k3)) == 0)
    {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    status = strlen("]");
    if (strncmp(s + result, "]", status) != 0)
    {
        return 0;
    }

    return (int)result + status;
}