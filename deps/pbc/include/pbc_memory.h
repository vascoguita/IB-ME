// Requires:
// * stdlib.h
#ifndef __PBC_MEMORY_H__
#define __PBC_MEMORY_H__

// Memory allocation functions used by PBC.
void *pbc_malloc(size_t);
void *pbc_realloc(void *, size_t);
void pbc_free(void *);

char *pbc_strdup(const char *s);

#endif //__PBC_MEMORY_H__
