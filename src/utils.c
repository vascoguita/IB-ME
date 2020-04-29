#include <stddef.h>

#include "utils.h"

void clip_sub(size_t *result, int status, size_t *left, size_t n) {
    *result += status;
    *left = *result >= n ? 0 : n - *result;
}