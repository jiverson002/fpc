/*

Copyright © 2006 Cornell Research Foundation, Inc.  All rights reserved.
Author: Professor Martin Burtscher

Software License Terms and Conditions

1. SOFTWARE shall mean the FPC code, or portions thereof, available via the web page http://www.csl.cornell.edu/~burtscher/research/FPC/ and described in Cornell Research Foundation, Inc. (“CRF”) file D-3944.  SOFTWARE includes, but is not limited to, source code, object code and executable code.

2. CRF is a wholly owned subsidiary of Cornell University, is a fiduciary of Cornell University in intellectual property matters and holds all intellectual property rights in SOFTWARE.

3. LICENSEE means the party to this Agreement and the user of SOFTWARE.  By using SOFTWARE, LICENSEE enters into this Agreement with CRF.

4. SOFTWARE is made available under this Agreement to allow certain non-commercial research and teaching use.  CRF reserves all commercial rights to SOFTWARE and these rights may be licensed by CRF to third parties.

5. LICENSEE is hereby granted permission to: a) use SOFTWARE for non-commercial research or teaching purposes, and b) download, compile, execute, copy, and modify SOFTWARE for non-commercial research or teaching purposes provided that this notice accompanies all copies of SOFTWARE.  Copies of modified SOFTWARE may be distributed only for non-commercial research or teaching purposes (i) if this notice accompanies those copies, (ii) if said copies carry prominent notices stating that SOFTWARE has been changed, and (iii) the date of any changes are clearly identified in SOFTWARE.

6. CRF may terminate this Agreement at any time if LICENSEE breaches a material provision of this Agreement.  CRF may also terminate this Agreement if the SOFTWARE becomes subject to any claim of infringement of patent, copyright or trade secret, or if in CRF’s opinion such a claim is likely to occur.

7. LICENSEE agrees that the export of SOFTWARE from the United States may require approval from the U.S. government and failure to obtain such approval will result in the immediate termination of this license and may result in criminal liability under U.S. laws.

8. The work leading to the development of SOFTWARE was supported in part by various grants from an agency of the U.S. Government, and CRF is obligated to comply with U.S. OMB Circular A-124 and 37 CFR Part 401.  This license is subject to the applicable terms of U.S. Government regulations concerning Government funded inventions.

9. CRF provides SOFTWARE on an “as is” basis.  CRF does not warrant, guarantee, or make any representations regarding the use or results of SOFTWARE with respect to its correctness, accuracy, reliability or performance.  The entire risk of the use and performance of SOFTWARE is assumed by LICENSEE.  ALL WARRANTIES INCLUDING, WITHOUT LIMITATION, ANY WARRANTY OF FITNESS FOR A PARTICULAR PURPOSE OR MERCHANTABILITY AND ANY WARRANTY OF NONINFRINGEMENT OF PATENTS, COPYRIGHTS, OR ANY OTHER INTELLECTUAL PROPERTY RIGHT ARE HEREBY EXCLUDED.

10. LICENSEE understands and agrees that neither CRF nor Cornell University is under any obligation to provide maintenance, support or update services, notices of latent defects, correction of defects, or future versions for SOFTWARE.

11. Even if advised of the possibility of damages, under no circumstances shall CRF or Cornell University individually or jointly be liable to LICENSEE or any third party for damages of any character, including, without limitation, direct, indirect, incidental, consequential or special damages, loss of profits, loss of use, loss of goodwill, computer failure or malfunction.  LICENSEE agrees to indemnify and hold harmless CRF and Cornell University for any and all liability CRF or Cornell University may incur as a result of use of SOFTWARE by LICENSEE.

*/

#include "fpc.h"

static const unsigned long long mask[8] = {
 0x0000000000000000ULL,
 0x00000000000000ffULL,
 0x000000000000ffffULL,
 0x0000000000ffffffULL,
 0x000000ffffffffffULL,
 0x0000ffffffffffffULL,
 0x00ffffffffffffffULL,
 0xffffffffffffffffULL
};

/* returns number of bytes written to 'out' */
static size_t
_fpc_compress(unsigned long const predsizem1,
              unsigned long long const * const in,
              unsigned char * out, size_t const size,
              struct fpc_context * const ctx)
{
  size_t i;
  unsigned long op, code, bcode;
  unsigned long long val, stride, xor1, xor2;

  unsigned long const psm1 = (1L << predsizem1) - 1;

  unsigned long long * fcm = ctx->wrkmem;
  unsigned long long * dfcm = ctx->wrkmem + psm1 + 1;
  unsigned long hash = ctx->hash;
  unsigned long dhash = ctx->dhash;
  unsigned long long lastval = ctx->lastval;
  unsigned long long pred1 = ctx->pred1;
  unsigned long long pred2 = ctx->pred2;

  /* adjust the pointer since we are not writing out the predsizem1 value,
   * which belongs in the first index of 'out' */
  out++;

  val = in[0];
  op = 6 + ((size + 1) >> 1);
  *((unsigned long long *)&out[(op >> 3) << 3]) = 0;

  for (i=0; i<size; i+=2) {
    xor1 = val ^ pred1;
    fcm[hash] = val;
    hash = ((hash << 6) ^ (val >> 48)) & psm1;
    pred1 = fcm[hash];

    stride = val - lastval;
    xor2 = val ^ (lastval + pred2);
    lastval = val;
    val = in[i + 1];
    dfcm[dhash] = stride;
    dhash = ((dhash << 2) ^ (stride >> 40)) & psm1;
    pred2 = dfcm[dhash];

    code = 0;
    if (xor1 > xor2) {
      code = 0x80;
      xor1 = xor2;
    }
    bcode = 7;                // 8 bytes
    if (0 == (xor1 >> 56))
      bcode = 6;              // 7 bytes
    if (0 == (xor1 >> 48))
      bcode = 5;              // 6 bytes
    if (0 == (xor1 >> 40))
      bcode = 4;              // 5 bytes
    if (0 == (xor1 >> 24))
      bcode = 3;              // 3 bytes
    if (0 == (xor1 >> 16))
      bcode = 2;              // 2 bytes
    if (0 == (xor1 >> 8))
      bcode = 1;              // 1 byte
    if (0 == xor1)
      bcode = 0;              // 0 bytes

    *((unsigned long long *)&out[(op >> 3) << 3]) |= xor1 << ((op & 0x7) << 3);
    if (0 == (op & 0x7))
      xor1 = 0;
    *((unsigned long long *)&out[((op >> 3) << 3) + 8]) = xor1 >> (64 - ((op & 0x7) << 3));

    op += bcode + (bcode >> 2);
    code |= bcode << 4;

    xor1 = val ^ pred1;
    fcm[hash] = val;
    hash = ((hash << 6) ^ (val >> 48)) & psm1;
    pred1 = fcm[hash];

    stride = val - lastval;
    xor2 = val ^ (lastval + pred2);
    lastval = val;
    val = in[i + 2];
    dfcm[dhash] = stride;
    dhash = ((dhash << 2) ^ (stride >> 40)) & psm1;
    pred2 = dfcm[dhash];

    bcode = code | 0x8;
    if (xor1 > xor2) {
      code = bcode;
      xor1 = xor2;
    }
    bcode = 7;                // 8 bytes
    if (0 == (xor1 >> 56))
      bcode = 6;              // 7 bytes
    if (0 == (xor1 >> 48))
      bcode = 5;              // 6 bytes
    if (0 == (xor1 >> 40))
      bcode = 4;              // 5 bytes
    if (0 == (xor1 >> 24))
      bcode = 3;              // 3 bytes
    if (0 == (xor1 >> 16))
      bcode = 2;              // 2 bytes
    if (0 == (xor1 >> 8))
      bcode = 1;              // 1 byte
    if (0 == xor1)
      bcode = 0;              // 0 bytes

    *((unsigned long long *)&out[(op >> 3) << 3]) |= xor1 << ((op & 0x7) << 3);
    if (0 == (op & 0x7))
      xor1 = 0;
    *((unsigned long long *)&out[((op >> 3) << 3) + 8]) = xor1 >> (64 - ((op & 0x7) << 3));

    op += bcode + (bcode >> 2);
    out[6 + (i >> 1)] = code | bcode;
  }
  if (0 != (size & 1)) {
    op -= bcode + (bcode >> 2);
  }
  out[0] = size;
  out[1] = size >> 8;
  out[2] = size >> 16;
  out[3] = op;
  out[4] = op >> 8;
  out[5] = op >> 16;

  return op;
}

/* returns number of bytes read from 'in' */
static size_t
_fpc_decompress(unsigned long const predsizem1, unsigned char const * in,
                unsigned long long * const out, size_t size,
                struct fpc_context * const ctx)
{
  size_t i;
  unsigned long ip, code, bcode, tmp;
  unsigned long long val, stride, next;

  unsigned long const psm1 = (1L << predsizem1) - 1;
  unsigned long long * fcm = ctx->wrkmem;
  unsigned long long * dfcm = ctx->wrkmem + psm1 + 1;
  unsigned long hash = ctx->hash;
  unsigned long dhash = ctx->dhash;
  unsigned long long lastval = ctx->lastval;
  unsigned long long pred1 = ctx->pred1;
  unsigned long long pred2 = ctx->pred2;

  size = in[3];
  size = (size << 8) | in[2];
  size = (size << 8) | in[1];
  ip = in[6];
  ip = (ip << 8) | in[5];
  ip = (ip << 8) | in[4];

  in += 7;
  ip = (size + 1) >> 1;

  for (i=0; i<size; i+=2) {
    code = in[i >> 1];

    val = *((long long *)&in[(ip >> 3) << 3]);
    next = *((long long *)&in[((ip >> 3) << 3) + 8]);
    tmp = (ip & 0x7) << 3;
    val = val >> tmp;
    next <<= 64 - tmp;
    if (0 == tmp)
      next = 0;
    val |= next;

    bcode = (code >> 4) & 0x7;
    val &= mask[bcode];
    ip += bcode + (bcode >> 2);

    if (0 != (code & 0x80))
      pred1 = pred2;
    val ^= pred1;

    fcm[hash] = val;
    hash = ((hash << 6) ^ (val >> 48)) & psm1;
    pred1 = fcm[hash];

    stride = val - lastval;
    dfcm[dhash] = stride;
    dhash = ((dhash << 2) ^ (stride >> 40)) & psm1;
    pred2 = val + dfcm[dhash];
    lastval = val;

    out[i] = val;

    val = *((long long *)&in[(ip >> 3) << 3]);
    next = *((long long *)&in[((ip >> 3) << 3) + 8]);
    tmp = (ip & 0x7) << 3;
    val = val >> tmp;
    next <<= 64 - tmp;
    if (0 == tmp)
      next = 0;
    val |= next;

    bcode = code & 0x7;
    val &= mask[bcode];
    ip += bcode + (bcode >> 2);

    if (0 != (code & 0x8))
      pred1 = pred2;
    val ^= pred1;

    fcm[hash] = val;
    hash = ((hash << 6) ^ (val >> 48)) & psm1;
    pred1 = fcm[hash];

    stride = val - lastval;
    dfcm[dhash] = stride;
    dhash = ((dhash << 2) ^ (stride >> 40)) & psm1;
    pred2 = val + dfcm[dhash];
    lastval = val;

    out[i + 1] = val;
  }

  return ip+6;
}

size_t
fpc_compress(unsigned long const predsizem1, void const * const in,
             void * const out, size_t const size,
             struct fpc_context * const ctx)
{
  return _fpc_compress(predsizem1, (unsigned long long *)in,
                       (unsigned char *)out, size, ctx);
}

size_t
fpc_decompress(unsigned long const predsizem1, void const * const in,
               void * const out, size_t const size,
               struct fpc_context * const ctx)
{
  return _fpc_decompress(predsizem1, (unsigned char *)in,
                         (unsigned long long *)out, size, ctx);
}

#if 0
#include <assert.h>
#include <string.h>

#define INPUT_SIZE 8192

int main(int argc, char *argv[])
{
  size_t i, j, k, size;
  long val;
  struct fpc_context ctx1, ctx2;
  unsigned long long in[INPUT_SIZE] __attribute__((aligned(8)));
  unsigned long long chk[INPUT_SIZE] __attribute__((aligned(8)));
  unsigned char out[6 + (INPUT_SIZE / 2) + (INPUT_SIZE * 8) + 2] __attribute__((aligned(8)));

  assert(4 <= sizeof(long));
  assert(8 == sizeof(long long));
  assert(0 < INPUT_SIZE);
  assert(0 == (INPUT_SIZE & 0xf));
  val = 1;
  assert(1 == *((char *)&val));

  if (argc > 1) {
    val = -1;
    val = atol(argv[1]);
    assert(0 <= val);
    assert(val < 256);

    memset(&ctx1, 0, sizeof(struct fpc_context));
    memset(&ctx2, 0, sizeof(struct fpc_context));
    ctx1.wrkmem = (unsigned long long *) calloc(2*(1L << val), sizeof(unsigned long long));
    ctx2.wrkmem = (unsigned long long *) calloc(2*(1L << val), sizeof(unsigned long long));

    out[0] = val;

    size = fread(in, 8, INPUT_SIZE, stdin);
    while (0 < size) {
      j = fpc_compress(val, in, out, size, &ctx1);
      k = fpc_decompress(val, out, chk, size, &ctx2);
      assert(j == k);

      for (i=0; i<size; ++i) {
        assert(in[i] == chk[i]);
      }

      size = fread(in, 8, INPUT_SIZE, stdin);
    }

    assert(!fread(&val, 1, 1, stdin));

    free(ctx1.wrkmem);
    free(ctx2.wrkmem);
  }

  return EXIT_SUCCESS;
}
#endif
