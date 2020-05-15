#include <stdlib.h>

#include "memory.h"

#include <tee_internal_api.h>


void* ibme_malloc(size_t size) {
    return TEE_Malloc(size, 0);
}

void ibme_free(void *ptr) {
    TEE_Free(ptr);
}