#ifndef X8A4_SECURE_CLEAR_H
#define X8A4_SECURE_CLEAR_H

#include <stddef.h>

/* Volatile stores keep sensitive buffers from being optimized away. */
static inline void x8A4_secure_clear(void *ptr, size_t size) {
  volatile unsigned char *p = (volatile unsigned char *)ptr;
  while (size--) *p++ = 0;
}

#endif
