#ifndef FPC_H
#define FPC_H

#include <stdlib.h>

#if defined (__cplusplus)
extern "C" {
#endif

size_t fpc_compress(long, void const*, void*, size_t);
size_t fpc_decompress(void const*, void*, size_t);

#if defined (__cplusplus)
}
#endif

#endif
