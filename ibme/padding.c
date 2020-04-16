#include <stdio.h>
#include <stdlib.h>

#include "padding.h"

int pad(const unsigned char *data, size_t data_len, Padded_data **p_d) {
    unsigned char padding_byte;
    int i;

    if((data == NULL) || (data_len < 1) || (data_len > ((*p_d)->len - 1)) || (((*p_d)->len - data_len) > 255)  || (*p_d == NULL)) {
        return 1;
    }

    padding_byte = (*p_d)->len - data_len;

    for(i = 0; i < data_len; i++) {
        ((*p_d)->p_d)[i] = data[i];
    }
    for(i = data_len; i < (*p_d)->len; i++) {
        ((*p_d)->p_d)[i] = padding_byte;
    }
    return 0;
}

int unpad(const Padded_data *p_d, unsigned char **data, size_t *data_len) {
    size_t data_len_tmp;
    int i;

    if((p_d == NULL) || (p_d->len < 1) || (*data == NULL) || (data_len == NULL)) {
        return 1;
    }

    if((p_d->p_d)[p_d->len - 1] > p_d->len) {
        *data_len = 0;
        return 0;
    }
    data_len_tmp = p_d->len - (p_d->p_d)[p_d->len - 1];

    for(i = data_len_tmp; i < p_d->len; i++) {
        if((p_d->p_d)[i] != (p_d->len - data_len_tmp)) {
            *data_len = 0;
            return 0;
        }
    }

    if(*data_len < data_len_tmp) {
        return 1;
    }

    for(i = 0; i < data_len_tmp; i++) {
        (*data)[i] = (p_d->p_d)[i];
    }
    *data_len = i;
    return 0;
}

int Padded_data_init(size_t p_d_len, Padded_data **p_d) {
    if((*p_d = (struct _padded_data *) malloc(sizeof(struct _padded_data))) == NULL) {
        return 1;
    }
    if(((*p_d)->len = p_d_len) < 1) {
        Padded_data_clear(*p_d);
        return 1;
    }
    if(((*p_d)->p_d = (unsigned char *)malloc((*p_d)->len * sizeof(unsigned char))) == NULL) {
        Padded_data_clear(*p_d);
        return 1;
    }
    return 0;
}

void Padded_data_clear(Padded_data *p_d) {
    if(p_d != NULL) {
        free(p_d->p_d);
        free(p_d);
    }
}