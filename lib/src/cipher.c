#include <pbc/pbc.h>
#include <string.h>

#include "cipher.h"
#include "hash.h"
#include <stdlib.h>
#include "utils.h"

Cipher *Cipher_init(pairing_t pairing)
{
    Cipher *c;
    if (!(c = (struct _cipher *)malloc(sizeof(struct _cipher))))
    {
        return NULL;
    }

    element_init_G1(c->T, pairing);
    if (!(c->T))
    {
        Cipher_clear(c);
        return NULL;
    }

    element_init_G1(c->U, pairing);
    if (!(c->U))
    {
        Cipher_clear(c);
        return NULL;
    }

    if ((c->V_size = Hash_bytes_length_from_pairing(pairing)) < 1)
    {
        Cipher_clear(c);
        return NULL;
    }

    if (!(c->V = (unsigned char *)malloc(c->V_size * sizeof(unsigned char))))
    {
        Cipher_clear(c);
        return NULL;
    }
    return c;
}

void Cipher_clear(Cipher *c)
{
    if (!c)
    {
        free(c->V);
        element_clear(c->U);
        element_clear(c->T);
        free(c);
    }
}

int Cipher_snprint(char *s, size_t n, Cipher *c)
{
    size_t result, left;
    int status, i;

    result = 0;

    status = snprintf(s, n, "[");
    if (status < 0)
    {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = element_snprint(s + result, left, c->T);
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
    status = element_snprint(s + result, left, c->U);
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
    status = snprintf(s + result, left, "%zu", c->V_size);
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
    for (i = 0; (size_t)i < c->V_size; i++)
    {
        status = snprintf(s + result, left, "%02x ", c->V[i]);
        if (status < 0)
        {
            return status;
        }
        clip_sub(&result, status, &left, n);
    }
    status = snprintf(s + result, left, "]");
    if (status < 0)
    {
        return status;
    }
    return (int)result + status;
}

int Cipher_set_str(char *s, size_t n, Cipher *c)
{
    size_t result, left;
    int status, i;

    result = 0;

    status = strlen("[");
    if (strncmp(s, "[", status) != 0)
    {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if ((status = element_set_str(c->T, s + result, 10)) == 0)
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
    if ((status = element_set_str(c->U, s + result, 10)) == 0)
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
    if ((c->V_size = strtoul(s + result, NULL, 0)) == 0)
    {
        return 0;
    }
    status = snprintf(NULL, 0, "%zu", c->V_size);
    clip_sub(&result, status, &left, n);
    status = strlen(", ");
    if (strncmp(s + result, ", ", status) != 0)
    {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    for (i = 0; (size_t)i < c->V_size; i++)
    {
        c->V[i] = strtoul(s + result, NULL, 16);
        status = snprintf(NULL, 0, "%02x ", c->V[i]);
        if (status < 0)
        {
            return status;
        }
        clip_sub(&result, status, &left, n);
    }
    status = strlen("]");
    if (strncmp(s + result, "]", status) != 0)
    {
        return 0;
    }

    return (int)result + status;
}