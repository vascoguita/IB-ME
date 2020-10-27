#include "padding.h"
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

int pad(const uint8_t *data, size_t data_size, uint8_t bs, uint8_t *p, size_t *p_size)
{
    uint8_t padding_byte;
    size_t tmp_p_size, i;

    tmp_p_size = (data_size / bs + 1) * bs;
    padding_byte = (uint8_t)(tmp_p_size - data_size);

    if((p == NULL) && (*p_size == 0)) {
        *p_size = tmp_p_size;
        return 0;
    }

    if(p == NULL || (*p_size != tmp_p_size)) {
        return 1;
    }

    memcpy(p, data, data_size);

    for(i = data_size; i < *p_size; i++) {
        p[i] = padding_byte;
    }

    return 0;
}

int unpad(const uint8_t *p, size_t p_size, uint8_t bs, uint8_t *data, size_t *data_size) {
    uint8_t padding_byte;
    size_t tmp_data_size, i;

    if (p == NULL || (p_size % bs)) {
        return 1;
    }

    padding_byte = p[p_size - 1];
    tmp_data_size = p_size - padding_byte;

    for (i = tmp_data_size; i < p_size; i++) {
        if (p[i] != padding_byte) {
            return 1;
        }
    }

    if ((data == NULL) && (*data_size == 0)) {
        *data_size = tmp_data_size;
        return 0;
    }
    if ((data == NULL) || (*data_size != tmp_data_size)) {
        return 1;
    }

    memcpy(data, p, *data_size);
    return 0;
}