#include <stdlib.h>
#include <string.h>
#include "pbc_utils.h"
#include "pbc_memory.h"

void *pbc_malloc(size_t size) {
  void *res = malloc(size);
  if (!res) pbc_die("malloc() error");
  return res;
}

void *pbc_realloc(void *ptr, size_t size) {
  void *res = realloc(ptr, size);
  if (!res) pbc_die("realloc() error");
  return res;
}

void pbc_free(void *ptr) { free(ptr); }

char *pbc_strdup(const char *s) {
  int len = strlen(s);
  char *res = pbc_malloc(len + 1);
  strcpy(res, s);
  return res;
}
