#ifndef IBME_MEMORY_H
#define IBME_MEMORY_H

#include <stddef.h>

void* ibme_malloc(size_t size);

void ibme_free(void *ptr);

#endif //IBME_MEMORY_H
