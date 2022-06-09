/*
 * aes.c - AES256 for Gnuk
 *
 * Copyright (C) 2020, 2022  Free Software Initiative of Japan
 * Author: NIIBE Yutaka <gniibe@fsij.org>
 *
 * This file is a part of Gnuk, a GnuPG USB Token implementation.
 *
 * Gnuk is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Gnuk is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
 * License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 *
 * This is an implementation using four T tables (little endian),
 * keysize fixed for AES-256.
 *
 */
/*
 * NOTE: This implementation is not safe against various kinds of
 * side-channel attacks.  For example, when it uses cache memory or
 * flash access accelerator, observing table access may be possible.
 */

/*
 * For AES-256:
 *
 * Block size in bit = 128, Nb = 4 (= 128 / 32) (in 32-bit word)
 * Key size in bit = 256, Nk = 8 (= 256 / 32) (in 32-bit word)
 * Number of round Nr = 14
 *
 * Contextsize = Nb * (Nr + 1) = 60 (in 32-bit word)
 */
#define Nr 14
#define Nk (AES_KEY_SIZE/4)

#include <string.h>
#include "aes.h"

static uint32_t
get_uint32_le (const unsigned char *b, unsigned int i)
{
  return (  ((uint32_t)b[i    ]      )
          | ((uint32_t)b[i + 1] <<  8)
          | ((uint32_t)b[i + 2] << 16)
          | ((uint32_t)b[i + 3] << 24));
}

static void
put_uint32_le (unsigned char *b, unsigned int i, uint32_t n)
{
  b[i    ] = (unsigned char) ((n)      );
  b[i + 1] = (unsigned char) ((n) >>  8);
  b[i + 2] = (unsigned char) ((n) >> 16);
  b[i + 3] = (unsigned char) ((n) >> 24);
}


/* Forward table */
#include "aes-t-table.c.in"

#define V(a,b,c,d) 0x##a##b##c##d
/* Note that We expose FT0 table.  */
const uint32_t FT0[256] = { FT };
#undef V

#define V(a,b,c,d) 0x##b##c##d##a
static const uint32_t FT1[256] = { FT };
#undef V

#define V(a,b,c,d) 0x##c##d##a##b
static const uint32_t FT2[256] = { FT };
#undef V

#define V(a,b,c,d) 0x##d##a##b##c
static const uint32_t FT3[256] = { FT };
#undef V

#undef FT

/* Round constants */
/*
 * Note: For AES-256, since (AES_CONTEXT_SIZE / Nk) = 7, we have no
 * carry-over in xtime computation for round constants, thus, the
 * irreducible polynomial doesn't matter at all.
 */
#define Rcon(i) (1 << i)


static void
key_expansion_step_0 (uint32_t *RK, unsigned int i)
{
  RK[8]  = RK[0] ^ (FT3[( RK[7] >>  8 ) & 0xff] & 0x000000ff)
                 ^ (FT0[( RK[7] >> 16 ) & 0Xff] & 0x0000ff00)
                 ^ (FT1[( RK[7] >> 24 ) & 0Xff] & 0x00ff0000)
                 ^ (FT2[( RK[7]       ) & 0xff] & 0xff000000)
                 ^ Rcon(i);
  RK[9]  = RK[1] ^ RK[8];
  RK[10] = RK[2] ^ RK[9];
  RK[11] = RK[3] ^ RK[10];
}

static void
key_expansion_step_1 (uint32_t *RK)
{
  RK[12] = RK[4] ^ (FT3[( RK[11]       ) & 0xff] & 0x000000ff)
                 ^ (FT0[( RK[11] >>  8 ) & 0xff] & 0x0000ff00)
                 ^ (FT1[( RK[11] >> 16 ) & 0xff] & 0x00ff0000)
                 ^ (FT2[( RK[11] >> 24 ) & 0xff] & 0xff000000);
  RK[13] = RK[5] ^ RK[12];
  RK[14] = RK[6] ^ RK[13];
  RK[15] = RK[7] ^ RK[14];
}

/*
 * AES key setup
 */
void
aes_set_key (aes_context *ctx, const unsigned char key[AES_KEY_SIZE])
{
  unsigned int i;
  uint32_t *RK = ctx->rk;

  /* Nk times */
  RK[0] = get_uint32_le (key,  0);
  RK[1] = get_uint32_le (key,  4);
  RK[2] = get_uint32_le (key,  8);
  RK[3] = get_uint32_le (key, 12);
  RK[4] = get_uint32_le (key, 16);
  RK[5] = get_uint32_le (key, 20);
  RK[6] = get_uint32_le (key, 24);
  RK[7] = get_uint32_le (key, 28);

  for (i = 0; i < (AES_CONTEXT_SIZE / Nk) - 1; i++)
    {
      key_expansion_step_0 (RK, i);
      key_expansion_step_1 (RK);
      RK += Nk;
    }

  key_expansion_step_0 (RK, i);
}


static uint32_t
round_calc_step (uint32_t y0, uint32_t y1, uint32_t y2, uint32_t y3)
{
  uint32_t x;

  x = FT0[( y0       ) & 0xff]
    ^ FT1[( y1 >>  8 ) & 0xff]
    ^ FT2[( y2 >> 16 ) & 0xff]
    ^ FT3[( y3 >> 24 ) & 0xff];
  return x;
}

#define ROUND(X0,X1,X2,X3,Y0,Y1,Y2,Y3)           \
  X0 = round_calc_step (Y0, Y1, Y2, Y3) ^ *RK++; \
  X1 = round_calc_step (Y1, Y2, Y3, Y0) ^ *RK++; \
  X2 = round_calc_step (Y2, Y3, Y0, Y1) ^ *RK++; \
  X3 = round_calc_step (Y3, Y0, Y1, Y2) ^ *RK++

static uint32_t
last_round_calc_step (uint32_t y0, uint32_t y1, uint32_t y2, uint32_t y3)
{
  uint32_t x;

  x = (FT3[( y0       ) & 0xff] & 0x000000ff)
    ^ (FT0[( y1 >>  8 ) & 0xff] & 0x0000ff00)
    ^ (FT1[( y2 >> 16 ) & 0xff] & 0x00ff0000)
    ^ (FT2[( y3 >> 24 ) & 0xff] & 0xff000000);
  return x;
}

#define LAST_ROUND(X0,X1,X2,X3,Y0,Y1,Y2,Y3)           \
  X0 = last_round_calc_step (Y0, Y1, Y2, Y3) ^ *RK++; \
  X1 = last_round_calc_step (Y1, Y2, Y3, Y0) ^ *RK++; \
  X2 = last_round_calc_step (Y2, Y3, Y0, Y1) ^ *RK++; \
  X3 = last_round_calc_step (Y3, Y0, Y1, Y2) ^ *RK++

/*
 * AES block encryption
 */
void
aes_encrypt (const aes_context *ctx,
             const unsigned char input[AES_BLOCK_SIZE],
             unsigned char output[AES_BLOCK_SIZE])
{
  uint32_t X0, X1, X2, X3, Y0, Y1, Y2, Y3;
  const uint32_t *RK = ctx->rk;

  /* Nb times */
  X0 = get_uint32_le (input,  0) ^ *RK++;
  X1 = get_uint32_le (input,  4) ^ *RK++;
  X2 = get_uint32_le (input,  8) ^ *RK++;
  X3 = get_uint32_le (input, 12) ^ *RK++;

  /* Nr-1 times */
  ROUND (Y0, Y1, Y2, Y3, X0, X1, X2, X3);
  ROUND (X0, X1, X2, X3, Y0, Y1, Y2, Y3);
  ROUND (Y0, Y1, Y2, Y3, X0, X1, X2, X3);
  ROUND (X0, X1, X2, X3, Y0, Y1, Y2, Y3);
  ROUND (Y0, Y1, Y2, Y3, X0, X1, X2, X3);
  ROUND (X0, X1, X2, X3, Y0, Y1, Y2, Y3);
  ROUND (Y0, Y1, Y2, Y3, X0, X1, X2, X3);
  ROUND (X0, X1, X2, X3, Y0, Y1, Y2, Y3);
  ROUND (Y0, Y1, Y2, Y3, X0, X1, X2, X3);
  ROUND (X0, X1, X2, X3, Y0, Y1, Y2, Y3);
  ROUND (Y0, Y1, Y2, Y3, X0, X1, X2, X3);
  ROUND (X0, X1, X2, X3, Y0, Y1, Y2, Y3);
  ROUND (Y0, Y1, Y2, Y3, X0, X1, X2, X3);

  /* And, then */
  LAST_ROUND (X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  /* Nb times */
  put_uint32_le (output,  0, X0);
  put_uint32_le (output,  4, X1);
  put_uint32_le (output,  8, X2);
  put_uint32_le (output, 12, X3);
}


/*
 * AES key teardown
 */
void
aes_clear_key (aes_context *ctx)
{
  memset (ctx->rk, 0, sizeof ctx->rk);
  /* to compiler: no removal of memset above, please */
  asm ("" : : "m" (ctx->rk) : "memory");
}

/*
 * AES counter mode encryption
 */
void
aes_ctr (const aes_context *ctx, uint8_t ctr_blk[AES_BLOCK_SIZE],
         const uint8_t *input, unsigned int len, uint8_t *output)
{
  uint32_t counter;

  counter = get_uint32_le (ctr_blk, 0);

  while (len)
    {
      uint8_t blk[AES_BLOCK_SIZE];
      int i, todo;

      todo = len < AES_BLOCK_SIZE ? len : AES_BLOCK_SIZE;

      aes_encrypt (ctx, ctr_blk, blk);
      counter++;
      put_uint32_le (ctr_blk, 0, counter);

      for (i = 0; i < todo; i++)
        *output++ = (*input++ ^ blk[i]);
      len -= todo;
    }
}
