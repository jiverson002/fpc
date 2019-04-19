#ifndef FPC_H
#define FPC_H

#include <stdlib.h>

struct fpc_context {
  unsigned long hash;
  unsigned long dhash;
  unsigned long long lastval;
  unsigned long long pred1;
  unsigned long long pred2;
  unsigned long long * wrkmem;
};

#if defined (__cplusplus)
extern "C" {
#endif

extern size_t
fpc_compress(
  unsigned long const predsizem1,
  void const * const in,
  void * const out,
  size_t const size,
  struct fpc_context * const ctx
);

extern size_t
fpc_decompress(
  unsigned long const predsizem1,
  void const * const in,
  void * const out,
  size_t const size,
  struct fpc_context * const ctx
);

#if defined (__cplusplus)
}
#endif

#endif
