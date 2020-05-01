#include <pbc.h>
#include <string.h>

#include "cipher.h"
#include "hash.h"
#include "memory.h"
#include "utils.h"

int Cipher_init(pairing_t pairing, Cipher **c) {
    if((*c = (struct _cipher*) ibme_malloc(sizeof(struct _cipher))) == NULL) {
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

    if(((*c)->V_len = Hash_bytes_length_from_pairing(pairing)) < 1) {
        Cipher_clear(*c);
        return 1;
    }

    if(((*c)->V = (unsigned char*) ibme_malloc((*c)->V_len * sizeof(unsigned char))) == NULL) {
        Cipher_clear(*c);
        return 1;
    }
    return 0;
}

void Cipher_clear(Cipher *c) {
    if(c != NULL) {
        ibme_free(c->V);
        element_clear(c->U);
        element_clear(c->T);
        ibme_free(c);
    }
}

int Cipher_snprint(char *s, size_t n, Cipher *c) {
    size_t result, left;
    int status, i;

    result = 0;

    status = snprintf(s, n, "[");
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = element_snprint(s + result, left, c->T);
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, ", ");
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = element_snprint(s + result, left, c->U);
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, ", ");
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, "%zu", c->V_len);
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    status = snprintf(s + result, left, ", ");
    if (status < 0) {
        return status;
    }
    clip_sub(&result, status, &left, n);
    for(i = 0; i < c->V_len; i++) {
        status = snprintf(s + result, left, "\\x%x", c->V[i]);
        if (status < 0) {
            return status;
        }
        clip_sub(&result, status, &left, n);
    }
    status = snprintf(s + result, left, "]");
    if (status < 0) {
        return status;
    }
    return (int)result + status;
}

int Cipher_set_str(char *s, size_t n, Cipher *c) {
    size_t result, left;
    int status, i;

    result = 0;

    status = strlen("[");
    if(strncmp(s, "[", status) != 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if((status = element_set_str(c->T, s + result, 10)) == 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    status = strlen(", ");
    if(strncmp(s + result, ", ", status) != 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if((status = element_set_str(c->U, s + result, 10)) == 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    status = strlen(", ");
    if(strncmp(s + result, ", ", status) != 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    if((c->V_len = strtoul(s + result, NULL, 0)) == 0) {
        return 0;
    }
    status = snprintf(NULL, 0, "%zu", c->V_len);
    clip_sub(&result, status, &left, n);
    status = strlen(", ");
    if(strncmp(s + result, ", ", status) != 0) {
        return 0;
    }
    clip_sub(&result, status, &left, n);
    for(i = 0; i < c->V_len; i++) {
        status = strlen("\\x");
        if(strncmp(s + result, "\\x", status) != 0) {
            return 0;
        }
        clip_sub(&result, status, &left, n);
        c->V[i] = strtoul(s + result, NULL, 16);
        status = snprintf(NULL, 0, "%x", c->V[i]);
        if (status < 0) {
            return status;
        }
        clip_sub(&result, status, &left, n);
    }
    status = strlen("]");
    if(strncmp(s + result, "]", status) != 0) {
        return 0;
    }

    return (int)result + status;
}