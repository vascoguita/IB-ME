#include <stdlib.h>

#include "memory.h"

void* ibme_malloc(size_t size) {
    return malloc(size);
}

void ibme_free(void *ptr) {
    free(ptr);
}