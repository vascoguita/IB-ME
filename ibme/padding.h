#ifndef IBME_PADDING_H
#define IBME_PADDING_H

// PKCS-PAD for data block with less than 256 padding bytes

typedef struct _padded_data {
    unsigned char *p_d;
    size_t len;
} Padded_data;

static const unsigned char max_padding = 0xff;

int pad(const unsigned char *data, size_t data_len, Padded_data **p_d);
int unpad(const Padded_data *p_d, unsigned char **data, size_t *data_len);

int Padded_data_init(size_t p_d_len, Padded_data **p_d);
void Padded_data_clear(Padded_data *p_d);

#endif //IBME_PADDING_H