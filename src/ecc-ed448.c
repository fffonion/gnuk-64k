/*                                                    -*- coding: utf-8 -*-
 * ecc-ed448.c - Elliptic curve computation for
 *               the twisted Edwards curve: -x^2 + y^2 = 1 + d*x^2*y^2
 *               d = -39081
 *
 * Copyright (C) 2021  Free Software Initiative of Japan
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdint.h>
#include <string.h>

#include "p448.h"
#include "shake256.h"


#define C_WORDS      7
#define BN448_WORDS 14
#define BN690_WORDS 22
#define BN896_WORDS 28
#define BN912_WORDS 29 /* 28.5 */

typedef struct bn448 {
  uint32_t word[ BN448_WORDS ]; /* Little endian */
} bn448;

typedef struct bn896 {
  uint32_t word[ BN896_WORDS ]; /* Little endian */
} bn896;

typedef struct bn912 {
  uint32_t word[ BN912_WORDS ]; /* Little endian */
} bn912;

static bn448 M[1] = {{{
  0xab5844f3, 0x2378c292, 0x8dc58f55, 0x216cc272,
  0xaed63690, 0xc44edb49, 0x7cca23e9, 0xffffffff,
  0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
  0xffffffff, 0x3fffffff
}}};

static uint32_t C[C_WORDS] = {
  0x54a7bb0d, 0xdc873d6d, 0x723a70aa, 0xde933d8d,
  0x5129c96f, 0x3bb124b6, 0x8335dc16
};


static uint32_t
bn448_add (bn448 *X, const bn448 *A, const bn448 *B)
{
  int i;
  uint32_t v;
  uint32_t carry = 0;
  uint32_t *px;
  const uint32_t *pa, *pb;

  px = X->word;
  pa = A->word;
  pb = B->word;

  for (i = 0; i < BN448_WORDS; i++)
    {
      v = *pb;
      *px = *pa + carry;
      carry = (*px < carry);
      *px += v;
      carry += (*px < v);
      px++;
      pa++;
      pb++;
    }

  return carry;
}

static uint32_t
bn448_sub (bn448 *X, const bn448 *A, const bn448 *B)
{
  int i;
  uint32_t v;
  uint32_t borrow = 0;
  uint32_t *px;
  const uint32_t *pa, *pb;

  px = X->word;
  pa = A->word;
  pb = B->word;

  for (i = 0; i < BN448_WORDS; i++)
    {
      uint32_t borrow0 = (*pa < borrow);

      v = *pb;
      *px = *pa - borrow;
      borrow = (*px < v) + borrow0;
      *px -= v;
      px++;
      pa++;
      pb++;
    }

  return borrow;
}


static void
bnX_mul_C (uint32_t *r, const uint32_t *q, int q_size)
{
  int i, j, k;
  int i_beg, i_end;
  uint32_t r0, r1, r2;

  r0 = r1 = r2 = 0;
  for (k = 0; k <= q_size + C_WORDS - 2; k++)
    {
      if (q_size < C_WORDS)
	if (k < q_size)
	  {
	    i_beg = 0;
	    i_end = k;
	  }
	else
	  {
	    i_beg = k - q_size + 1;
	    i_end = k;
	    if (i_end > C_WORDS - 1)
	      i_end = C_WORDS - 1;
	  }
      else
	if (k < C_WORDS)
	  {
	    i_beg = 0;
	    i_end = k;
	  }
	else
	  {
	    i_beg = k - C_WORDS + 1;
	    i_end = k;
	    if (i_end > q_size - 1)
	      i_end = q_size - 1;
	  }

      for (i = i_beg; i <= i_end; i++)
	{
	  uint64_t uv;
	  uint32_t u, v;
	  uint32_t carry;

	  j = k - i;
	  if (q_size < C_WORDS)
	    uv = ((uint64_t)q[j])*((uint64_t)C[i]);
	  else
	    uv = ((uint64_t)q[i])*((uint64_t)C[j]);
	  v = uv;
	  u = (uv >> 32);
	  r0 += v;
	  carry = (r0 < v);
	  r1 += carry;
	  carry = (r1 < carry);
	  r1 += u;
	  carry += (r1 < u);
	  r2 += carry;
	}

      r[k] = r0;
      r0 = r1;
      r1 = r2;
      r2 = 0;
    }

  r[k] = r0;
}

/* X <= X + A when COND!=0 */
/* X <= X when COND==0 */
static void
bn448_add_cond (bn448 *X, const bn448 *A, int cond)
{
  int i;
  uint32_t v;
  uint32_t carry = 0;
  uint32_t *px;
  const uint32_t *pa;
  uint32_t mask = -(!!cond);

  px = X->word;
  pa = A->word;

  for (i = 0; i < BN448_WORDS; i++)
    {
      v = *px;
      *px = (*pa & mask) + carry;
      carry = (*px < carry);
      *px += v;
      carry += (*px < v);
      px++;
      pa++;
    }
}


/* X <= X + A mod M */
static void
bn448_addm (bn448 *X, const bn448 *A)
{
  uint32_t borrow;

  bn448_add (X, X, A);
  borrow = bn448_sub (X, X, M);
  bn448_add_cond (X, M, borrow);
}

/**
 * @brief R = A mod M (using M=2^446-C) (Barret reduction)
 *
 * See HAC 14.47.
 */
void
mod_reduce_M (bn448 *R, const bn912 *A)
{
  uint32_t q[BN448_WORDS+1];
  uint32_t tmp[BN690_WORDS];
  bn448 r[1];
  uint32_t carry, next_carry;
  int i;

  /* Q = A / 2^446 *//* 466-bit */
  /* Upper half of A->word[28] must be zero.  */
  q[14] = (A->word[28] << 2) | (A->word[27] >> 30);
  carry = A->word[27] & 0x3fffffff;
  for (i = BN448_WORDS - 1; i >= 0; i--)
    {
      next_carry = A->word[i+13] & 0x3fffffff;
      q[i] = (A->word[i+13] >> 30) | (carry << 2);
      carry = next_carry;
    }
  memcpy (R, A, sizeof (bn448));
  R->word[13] &= 0x3fffffff;

  /* Q_size: 15 *//* 466-bit */
  bnX_mul_C (tmp, q, 15); /* TMP = Q*C *//* 690-bit */
  /* Q = tmp / 2^446 *//* 244-bit */
  carry = tmp[21];
  for (i = 7; i >= 0; i--)
    {
      next_carry = tmp[i+13] & 0x3fffffff;
      q[i] = (tmp[i+13] >> 30) | (carry << 2);
      carry = next_carry;
    }
  /* R' = tmp % 2^446 */
  memcpy (r, tmp, sizeof (bn448));
  r->word[13] &= 0x3fffffff;
  /* R += R' */
  bn448_addm (R, r);

  /* Q_size: 8 *//* 244-bit */
  bnX_mul_C (tmp, q, 8); /* TMP = Q*C *//* 468-bit */
  /* Q = tmp / 2^446 *//* 22-bit */
  carry = tmp[14];
  q[0] = (tmp[13] >> 30) | (carry << 2);
  /* R' = tmp % 2^446 */
  memcpy (r, tmp, sizeof (bn448));
  r->word[13] &= 0x3fffffff;
  /* R += R' */
  bn448_addm (R, r);

  /* Q_size: 1 */
  bnX_mul_C (tmp, q, 1); /* TMP = Q*C *//* 246-bit */
  /* R' = tmp % 2^446 */
  memset (((uint8_t *)r)+(sizeof (uint32_t)*8), 0, sizeof (uint32_t)*6);
  memcpy (r, tmp, sizeof (uint32_t)*8);
  /* R += R' */
  bn448_addm (R, r);
}


static void
bn448_mul (bn896 *X, const bn448 *A, const bn448 *B)
{
  int i, j, k;
  int i_beg, i_end;
  uint32_t r0, r1, r2;

  r0 = r1 = r2 = 0;
  for (k = 0; k <= (BN448_WORDS - 1)*2; k++)
    {
      if (k < BN448_WORDS)
	{
	  i_beg = 0;
	  i_end = k;
	}
      else
	{
	  i_beg = k - BN448_WORDS + 1;
	  i_end = BN448_WORDS - 1;
	}

      for (i = i_beg; i <= i_end; i++)
	{
	  uint64_t uv;
	  uint32_t u, v;
	  uint32_t carry;

	  j = k - i;

	  uv = ((uint64_t )A->word[i])*((uint64_t )B->word[j]);
	  v = uv;
	  u = (uv >> 32);
	  r0 += v;
	  carry = (r0 < v);
	  r1 += carry;
	  carry = (r1 < carry);
	  r1 += u;
	  carry += (r1 < u);
	  r2 += carry;
	}

      X->word[k] = r0;
      r0 = r1;
      r1 = r2;
      r2 = 0;
    }

  X->word[k] = r0;
}

static p448_t Gx[1] = { { {
      0x070cc05e, 0x026a82bc, 0x00938e26, 0x080e18b0,
      0x0511433b, 0x0f72ab66, 0x0412ae1a, 0x0a3d3a46,
      0x0a6de324, 0x00f1767e, 0x04657047, 0x036da9e1,
      0x05a622bf, 0x0ed221d1, 0x066bed0d, 0x04f1970c
    }
  }
};

static p448_t Gy[1] = { { {
      0x0230fa14, 0x008795bf, 0x07c8ad98, 0x0132c4ed,
      0x09c4fdbd, 0x01ce67c3, 0x073ad3ff, 0x005a0c2d,
      0x07789c1e, 0x0a398408, 0x0a73736c, 0x0c7624be,
      0x003756c9, 0x02488762, 0x016eb6bc, 0x0693f467
    }
  }
};

static p448_t Gz[1] = { { {
      0x00000001, 0x00000000, 0x00000000, 0x00000000,
      0x00000000, 0x00000000, 0x00000000, 0x00000000,
      0x00000000, 0x00000000, 0x00000000, 0x00000000,
      0x00000000, 0x00000000
    }
  }
};

static void
compute_kG_448 (uint8_t *out, const uint8_t *r)
{
  int i, j;
  p448_t x0[1], y0[1], z0[1]; /* P0 */
  p448_t x1[1], y1[1], z1[1]; /* P1 */

  /* P0 <= O */
  memset (x0, 0, sizeof (p448_t));
  memset (y0, 0, sizeof (p448_t));
  memset (z0, 0, sizeof (p448_t));
  y0->limb[0] = 1;
  z0->limb[0] = 1;

  for (i = 0; i < 56; i++)
    {
      for (j = 0; j < 8; j++)
	{
	  p448_t a[1], b[1], c[1], d[1];
	  p448_t e[1], f[1], g[1], h[1];
	  p448_t tmp0[1], tmp1[1];

	  /* Point double P1 <= P0 + P0 */
	  p448_add (tmp0, x0, y0);
	  p448_sqr (b, tmp0);
	  p448_sqr (c, x0);
	  p448_sqr (d, y0);
	  p448_add (e, c, d);
	  p448_sqr (h, z0);
	  p448_add (tmp0, h, h);
	  p448_sub (tmp1, e, tmp0);
	  p448_sub (tmp0, b, e);
	  p448_mul (x1, tmp0, tmp1);
	  p448_sub (tmp0, c, d);
	  p448_mul (y1, e, tmp0);
	  p448_mul (z1, e, tmp1);
	  /*
	    B = (X1+Y1)^2
	    C = X1^2
	    D = Y1^2
	    E = C+D
	    H = Z1^2
	    J = E-2*H
	    X3 = (B-E)*J
	    Y3 = E*(C-D)
	    Z3 = E*J
	  */

	  if ((r[56 - i - 1] & (1 << (7 - j))))
	    {
	      /* Point addition P0 <= P1 + G */
	      p448_mul (a, z1, Gz);
	      p448_sqr (b, a);
	      p448_mul (c, x1, Gx);
	      p448_mul (d, y1, Gy);
	      p448_mul (tmp0, c, d);
	      p448_mul_39081 (e, tmp0);
	      p448_add (f, b, e);
	      p448_sub (g, b, e);
	      p448_add (tmp0, x1, y1);
	      p448_add (tmp1, Gx, Gy);
	      p448_mul (h, tmp0, tmp1);
	      p448_sub (tmp0, h, c);
	      p448_sub (tmp1, tmp0, d);
	      p448_mul (tmp0, f, tmp1);
	      p448_mul (x0, a, tmp0);
	      p448_sub (tmp0, d, c);
	      p448_mul (tmp1, g, tmp0);
	      p448_mul (y0, a, tmp1);
	      p448_mul (z0, f, g);
	      /*
		 A = Z1*Z2
		 B = A^2
		 C = X1*X2
		 D = Y1*Y2
		 E = d*C*D
		 F = B-E
		 G = B+E
		 H = (X1+Y1)*(X2+Y2)
		 X3 = A*F*(H-C-D)
		 Y3 = A*G*(D-C)
		 Z3 = F*G
	      */
	    }
	  else
	    {
	      /* Point copy P0 <= P1 */
	      *x0 = *x1;
	      *y0 = *y1;
	      *z0 = *z1;
	    }
	}
    }

  /* Convert to affine coordinate.  */
  p448_inv (z1, z0);
  p448_mul (x1, x0, z1);
  p448_mul (y1, y0, z1);

  p448_serialize (out, x1);
  /* EdDSA encoding.  */
  out[56] = (out[0] & 1) << 7;
  p448_serialize (out, y1);
}


#define SEED_SIZE 57

#define DOM448       "SigEd448"
#define DOM448_LEN   8

int
eddsa_sign_448 (uint8_t *out, const uint8_t *input, unsigned int ilen, 
		const uint8_t *a_in, const uint8_t *seed, const uint8_t *pk)
{
  bn448 a[1], k[1], s[1];
  shake_context ctx;
  const unsigned char x_olen[2] = { 0, 0 };
  uint32_t hash[BN912_WORDS];
  uint8_t *r;
  uint32_t carry, borrow;

  memset (hash, 0, sizeof (hash));

  r = out;

  memcpy (a, a_in, sizeof (bn448));
  a->word[13] |= 0x80000000;
  a->word[0] &= ~3;

  shake256_start (&ctx);
  shake256_update (&ctx, DOM448, DOM448_LEN);
  shake256_update (&ctx, x_olen, 2);
  shake256_update (&ctx, seed, 57);
  shake256_update (&ctx, input, ilen);
  shake256_finish (&ctx, (uint8_t *)hash, 2*57);

  mod_reduce_M (k, (const bn912 *)hash);
  compute_kG_448 (r, (uint8_t *)k);

  shake256_start (&ctx);
  shake256_update (&ctx, DOM448, DOM448_LEN);
  shake256_update (&ctx, x_olen, 2);
  shake256_update (&ctx, r, 57);
  shake256_update (&ctx, pk, 57);
  shake256_update (&ctx, input, ilen);
  shake256_finish (&ctx, (uint8_t *)hash, 2*57);

  mod_reduce_M (s, (const bn912 *)hash);

  memset (hash, 0, sizeof (hash));
  bn448_mul ((bn896 *)hash, s, a);
  mod_reduce_M (s, (const bn912 *)hash);

  carry = bn448_add (s, s, k);
  borrow = bn448_sub (s, s, M);
  bn448_add_cond (s, M, (borrow && !carry));

  memcpy (out+57, s, 56);
  out[114-1] = 0;

  return 0;
}


void
eddsa_public_key_448 (uint8_t *pk, const uint8_t *a_in)
{

  bn448 a[1];

  memcpy (a, a_in, sizeof (bn448));
  a->word[13] |= 0x80000000;
  a->word[0] &= ~3;

  compute_kG_448 (pk, (uint8_t *)a);
}
