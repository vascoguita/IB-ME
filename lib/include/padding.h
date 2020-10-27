#ifndef IBME_PADDING_H
#define IBME_PADDING_H

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

int pad(const uint8_t *data, size_t data_size, uint8_t bs, uint8_t *p, size_t *p_size);
int unpad(const uint8_t *p, size_t p_size, uint8_t bs, uint8_t *data, size_t *data_size);

#endif //IBME_PADDING_H