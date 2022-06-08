/*
 * gcm-siv.c - GCM-SIV implementation
 *
 * Copyright (C) 2022  Free Software Initiative of Japan
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
 */

#include <stdint.h>

/*
 * The finite field GF(2^128) is defined by the irreducible
 * polynomial: X^128 + X^127 + X^126 + X^121 + 1
 *
 */

/*
 * 64-bit x 64-bit => 128-bit  carryless multiplication
 *
 * R <= A * B
 */
static void
clmul (uint64_t r[2], uint64_t a, uint64_t b)
{
  int i;

  r[0] = 0;
  r[1] = 0;
	
  for (i = 0; i < 64; i++)
    {
      uint64_t mask, lsb_r1;

      mask = 0UL - ((b & 1) == 1);
      /*
       * bit             mask
       *  1  ffffffffffffffff
       *  0  0000000000000000
       */
      r[1] ^= (a & mask);
      b >>= 1;
		
      /* Shift right */
      lsb_r1 = (r[1] & 1);
      r[1] >>= 1;
      r[0] >>= 1;
      r[0] |= (lsb_r1 << 63);
    }
}

/*
 * Constant 64-bit x 64-bit => 128-bit  carryless multiplication
 *
 * R <= 0xc200_0000_0000_0000 * A
 */
static void
clmul_0xc2 (uint64_t r[2], uint64_t a)
{
  uint64_t lsb_r1;

  /* 0xc2 = 0b1100001 */

  r[0] = 0;
  r[1] = 0;
	
  /* Compute for 0b__00001 */
  r[1] ^= a;
  lsb_r1 = (r[1] & 0x1f);
  r[1] >>= 5;
  r[0] >>= 5;
  r[0] |= (lsb_r1 << 59);

  /* Compute for 0b_1 */
  r[1] ^= a;
  lsb_r1 = (r[1] & 1);
  r[1] >>= 1;
  r[0] >>= 1;
  r[0] |= (lsb_r1 << 63);

  /* Compute for 0b1 */
  r[1] ^= a;
  lsb_r1 = (r[1] & 1);
  r[1] >>= 1;
  r[0] >>= 1;
  r[0] |= (lsb_r1 << 63);
}

/*
 * Montgomery Multiplication
 *
 * R, A, B: An element in GF(2^128) represented by 128-bit
 * (Polynomial of X of binary coefficients)
 *
 * R <= A * B * X^-128 mod p(X)
 *
 * X^128: the Montgomery basis
 */
static void
gfmul_mont (uint64_t r[2], const uint64_t a[2], const uint64_t b[2])
{  
  uint64_t tmp1[2], tmp2[2], tmp3[2];

  /* Karatsuba multiplication */
  clmul (tmp1, a[0], b[0]);
  clmul (tmp2, a[1], b[1]);
  clmul (tmp3, a[0] ^ a[1], b[0] ^ b[1]);

  r[1] = tmp2[1];
  r[0] = tmp2[1] ^ tmp2[0] ^ tmp1[1] ^ tmp3[1];
  tmp3[1] = tmp1[1] ^ tmp2[0] ^ tmp1[0] ^ tmp3[0];
  tmp3[0] = tmp1[0];

  /* Montgomery reduction */
  clmul_0xc2 (tmp1, tmp3[0]);
  tmp1[1] ^= tmp3[0];
  tmp1[0] ^= tmp3[1];

  clmul_0xc2 (tmp2, tmp1[0]);
  tmp2[1] ^= tmp1[0];
  tmp2[0] ^= tmp1[1];
	
  r[1] ^= tmp2[1];
  r[0] ^= tmp2[0];
}

static void
POLYVAL (const uint64_t *H, const uint8_t *input, unsigned int len,
         uint64_t *result)
{	
  uint64_t in[2];
  int i;
  int blocks = len/16;

  if (blocks == 0)
    return;
	
  for (i = 0; i < blocks; i++)
    {
      in[0] = (uint64_t)input[16*i] | ((uint64_t)input[16*i+1] << 8)
        | ((uint64_t)input[16*i+2] << 16) | ((uint64_t)input[16*i+3] << 24)
        | ((uint64_t)input[16*i+4] << 32) | ((uint64_t)input[16*i+5] << 40)
        | ((uint64_t)input[16*i+6] << 48) | ((uint64_t)input[16*i+7] << 56);
      in[1] = (uint64_t)input[16*i+8] | ((uint64_t)input[16*i+9] << 8)
        | ((uint64_t)input[16*i+10] << 16) | ((uint64_t)input[16*i+11] << 24)
        | ((uint64_t)input[16*i+12] << 32) | ((uint64_t)input[16*i+13] << 40)
        | ((uint64_t)input[16*i+14] << 48) | ((uint64_t)input[16*i+15] << 56);
		
      result[0] ^= in[0];
      result[1] ^= in[1];
      gfmul_mont (result, H, result);
    }
}
