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

static p448_t nGx[16] = {
  { { 0x00000000, 0x00000000, 0x00000000, 0x00000000,
      0x00000000, 0x00000000, 0x00000000, 0x00000000,
      0x00000000, 0x00000000, 0x00000000, 0x00000000,
      0x00000000, 0x00000000, 0x00000000, 0x00000000 } },
  { { 0x070cc05e, 0x026a82bc, 0x00938e26, 0x080e18b0,
      0x0511433b, 0x0f72ab66, 0x0412ae1a, 0x0a3d3a46,
      0x0a6de324, 0x00f1767e, 0x04657047, 0x036da9e1,
      0x05a622bf, 0x0ed221d1, 0x066bed0d, 0x04f1970c } },
  { { 0x05555555, 0x05555555, 0x05555555, 0x05555555,
      0x05555555, 0x05555555, 0x05555555, 0x05555555,
      0x0aaaaaa9, 0x0aaaaaaa, 0x0aaaaaaa, 0x0aaaaaaa,
      0x0aaaaaaa, 0x0aaaaaaa, 0x0aaaaaaa, 0x0aaaaaaa } },
  { { 0x06ff2f8f, 0x02817328, 0x0da85757, 0x0b769465,
      0x0fd6e862, 0x0f7f6271, 0x08daa9cb, 0x04a3fcfe,
      0x02ba077a, 0x0da82c7e, 0x041b8b8c, 0x09433322,
      0x04316cb6, 0x06455bd6, 0x0b9108af, 0x00865886 } },
  { { 0x08ba7f30, 0x0ce42ac4, 0x09e120e2, 0x0e179894,
      0x08ba21ae, 0x0f1515dd, 0x0301b7bd, 0x070c74cc,
      0x03fda4be, 0x00891c69, 0x0a09cf4e, 0x029ea255,
      0x017226f9, 0x02c1419a, 0x0c6c0cce, 0x049dcbc5 } },
  { { 0x02030034, 0x0a99d109, 0x06f950d0, 0x02d8cefc,
      0x0c96f07b, 0x07a920c3, 0x008bc0d5, 0x09588128,
      0x06d761e8, 0x062ada75, 0x0bcf7285, 0x00def80c,
      0x001eedb5, 0x00e2ba76, 0x05a48dcb, 0x07a9f933 } },
  { { 0x0abef79c, 0x07fd7652, 0x0443a878, 0x06c20a07,
      0x012a7109, 0x05c1840d, 0x0876451c, 0x04a06e4a,
      0x0ad95f65, 0x03bed0b4, 0x03fb0260, 0x025d2e67,
      0x0aebd971, 0x02e00349, 0x04498b72, 0x054523e0 } },
  { { 0x0eb5eaf7, 0x0df9567c, 0x078ac7d7, 0x0110a6b4,
      0x04706e0b, 0x02d33501, 0x00b5a209, 0x00df9c7b,
      0x0568e684, 0x0ba4223d, 0x08c3719b, 0x0d78af2d,
      0x0a5291b6, 0x077467b9, 0x05c89bef, 0x0079748e } },
  { { 0x0153bde0, 0x02538a67, 0x0406b696, 0x0223aca9,
      0x01ad713e, 0x0f9080dc, 0x0d816a64, 0x06c4cb47,
      0x05dc8b97, 0x0bc28568, 0x0c08e2d7, 0x0d97b037,
      0x05d0e66b, 0x05b63fb4, 0x0520e8a3, 0x0d1f1bc5 } },
  { { 0x06ab686b, 0x03d0def7, 0x049f7c79, 0x01a467ec,
      0x0c8989ed, 0x03e53f4f, 0x0430a0d9, 0x0101e344,
      0x08ad44ee, 0x0a3ae731, 0x0ae1d134, 0x0aefa6cd,
      0x0824ad4d, 0x0aa8cd7d, 0x0ed584fc, 0x0ef1650c } },
  { { 0x00ed303d, 0x0403165d, 0x0122d73b, 0x065118a0,
      0x01ce3dab, 0x0bc80576, 0x0ca61622, 0x0172278a,
      0x0134d3e8, 0x07e5c034, 0x06452c78, 0x035f7193,
      0x030d1c32, 0x01cdd35d, 0x0d19f641, 0x077486f9 } },
  { { 0x054dc10a, 0x0ef4da02, 0x05940db8, 0x06311865,
      0x082f2948, 0x0e20b149, 0x05581dba, 0x067b9377,
      0x004f5029, 0x0422ee71, 0x05122d34, 0x05d440db,
      0x01a4c640, 0x0b1e56d7, 0x0c2408ee, 0x0bf12abb } },
  { { 0x037dacc4, 0x058f07a0, 0x09997686, 0x08c1e6ff,
      0x09136d4d, 0x0db485de, 0x0a57b108, 0x038ec916,
      0x01a4bffa, 0x00753cea, 0x04388d69, 0x09a696e5,
      0x07d22687, 0x023a58a1, 0x021953a3, 0x020da156 } },
  { { 0x02ffb1f1, 0x0009135f, 0x08f9c605, 0x0099fc7e,
      0x026bfa5a, 0x0cc67da6, 0x0344552b, 0x0c186d12,
      0x01b339e1, 0x0b523250, 0x0c9708c5, 0x070a544f,
      0x01e928e7, 0x006baaec, 0x0ef0f50f, 0x00baedd2 } },
  { { 0x0e67a9ea, 0x09b527c6, 0x02c9cd63, 0x0e3d3936,
      0x08b37367, 0x08caded7, 0x073e4d68, 0x03cb6e83,
      0x0e3d3455, 0x0abfb9d9, 0x05cff643, 0x0556d891,
      0x05852c65, 0x01643f40, 0x0ebf7f41, 0x0c8d60e7 } },
  { { 0x024729d9, 0x0525d45f, 0x08712327, 0x05768aba,
      0x043035db, 0x0a25e43b, 0x0927ef21, 0x015a1ee8,
      0x06056112, 0x0a785d21, 0x0d508af9, 0x045e2fbf,
      0x037ba969, 0x0b6f721a, 0x0216d8d3, 0x030d6d8c } }
};

static p448_t nGy[16] = {
  { { 0x00000001, 0x00000000, 0x00000000, 0x00000000,
      0x00000000, 0x00000000, 0x00000000, 0x00000000,
      0x00000000, 0x00000000, 0x00000000, 0x00000000,
      0x00000000, 0x00000000, 0x00000000, 0x00000000 } },
  { { 0x0230fa14, 0x008795bf, 0x07c8ad98, 0x0132c4ed, 
      0x09c4fdbd, 0x01ce67c3, 0x073ad3ff, 0x005a0c2d, 
      0x07789c1e, 0x0a398408, 0x0a73736c, 0x0c7624be, 
      0x003756c9, 0x02488762, 0x016eb6bc, 0x0693f467 } },
  { { 0x0a9386ed, 0x0eafbcde, 0x0da06bda, 0x0b2bed1c, 
      0x0098bbbc, 0x0833a2a3, 0x080d6565, 0x08ad8c4b, 
      0x07e36d72, 0x0884dd7b, 0x0ed7a035, 0x0c2b0036, 
      0x06205086, 0x08db359d, 0x034ad704, 0x0ae05e96 } },
  { { 0x088ed6fc, 0x022ac135, 0x002dafb8, 0x09a68fed, 
      0x07f0bffa, 0x01bdb676, 0x08bb3a33, 0x0ec4e1d5, 
      0x0ce43c82, 0x056c3b9f, 0x0a8d9523, 0x0a6449a4, 
      0x0a7ad43a, 0x0f706cbd, 0x0bd5125c, 0x0e005a8d } },
  { { 0x0de51839, 0x0e236f86, 0x0d4f5b32, 0x044285d0, 
      0x0472b5d4, 0x07ea1ca9, 0x01c0d8f9, 0x07b8a5bc, 
      0x090dc322, 0x057d845c, 0x07c02f04, 0x01b979cb, 
      0x03a5de02, 0x027164b3, 0x04accde5, 0x0d49077e } },
  { { 0x02f435eb, 0x0b473147, 0x0f225443, 0x05512881, 
      0x033c5840, 0x0ee59d2b, 0x0127d7a4, 0x0b698017, 
      0x086551f7, 0x0b18fced, 0x0ca1823a, 0x00ade260, 
      0x0ce4fd58, 0x0d3b9109, 0x0a2517ed, 0x0adfd751 } },
  { { 0x007c7bcc, 0x0ea5d1da, 0x038ea98c, 0x0cce7769, 
      0x061d2b3e, 0x080284e8, 0x06e1ff1b, 0x048de76b, 
      0x09c58522, 0x07b12186, 0x02765a1a, 0x0bfd053a, 
      0x0056c667, 0x02d743ec, 0x0d8ab61c, 0x03f99b9c } },
  { { 0x0dac377f, 0x0e20d3fa, 0x072b5c09, 0x034e8669, 
      0x0c40bbb7, 0x0d8687a3, 0x0d2f84c9, 0x07b3946f, 
      0x0a78f50e, 0x0d00e40c, 0x017e7179, 0x0b875944, 
      0x0cb23583, 0x09c7373b, 0x0c90fd69, 0x07ddeda3 } },
  { { 0x0e69e09b, 0x04eb873c, 0x0bc8ee45, 0x01663164, 
      0x0ba8d89f, 0x008f7003, 0x0386ad82, 0x04b98ead, 
      0x0bd94c7b, 0x0a4b93b7, 0x0c6b38b3, 0x046ba408, 
      0x0f3574ff, 0x0dae87d1, 0x0e9bea9b, 0x0c7564f4 } },
  { { 0x04f4754f, 0x0a74df67, 0x0ef3fb8b, 0x0f52cea8, 
      0x02971140, 0x047c32d4, 0x0a256fbb, 0x0391c15d, 
      0x0a605671, 0x0c165fab, 0x087993b9, 0x0f2518c6, 
      0x0bd5a84d, 0x02daf7ac, 0x098f12ae, 0x01560b62 } },
  { { 0x04cddf67, 0x0954a89e, 0x0d85b6b1, 0x06381428, 
      0x0bdc0c7e, 0x097dc1aa, 0x0bf93c19, 0x068ff5d0, 
      0x07ee293a, 0x0da1d1bf, 0x0c17381a, 0x0e618e8a, 
      0x00fe7e94, 0x01024f1f, 0x0b026be1, 0x04d2fea0 } },
  { { 0x0016af01, 0x00cc9f86, 0x0f3d8cab, 0x088366ab, 
      0x0a2efe12, 0x085dda13, 0x05d00674, 0x0390df60, 
      0x06d187f7, 0x0f18f580, 0x0f0c5d20, 0x028c900f, 
      0x03e01733, 0x0ad30812, 0x054bf2fd, 0x042d35b5 } },
  { { 0x03d41ea7, 0x07e441cc, 0x0bebb2d1, 0x0b94c4fe, 
      0x06c7b42f, 0x046c255a, 0x0cad1da3, 0x0d7e2dc4, 
      0x03a3fd49, 0x045849c2, 0x03210658, 0x052e7646, 
      0x04560bbe, 0x003ff734, 0x0a92ca3c, 0x04dd13bb } },
  { { 0x0bf479e5, 0x0535d6d8, 0x0e4ec3e9, 0x0156e536, 
      0x0ddb9be2, 0x03165741, 0x059fd736, 0x0988af71, 
      0x02e33ddd, 0x013d8a78, 0x04e69002, 0x05460421, 
      0x0804a268, 0x034d56e0, 0x00e52a4c, 0x0c59b84f } },
  { { 0x00cf807c, 0x017eec50, 0x0c03470f, 0x06541d96, 
      0x00eabf76, 0x07cad92a, 0x0e7df219, 0x0c911c28, 
      0x0e7b71af, 0x080eedc1, 0x04222bfc, 0x07171dd0, 
      0x06bd4ceb, 0x064c867f, 0x0e2ce4db, 0x066a27ba } },
  { { 0x052074c3, 0x03065e08, 0x02a0684e, 0x0fa40b4a, 
      0x0763f955, 0x0851325a, 0x09f25900, 0x0d4ef19c, 
      0x0f665756, 0x0799c869, 0x03312990, 0x07b05222, 
      0x028db802, 0x0c986c2b, 0x028ade0a, 0x0f48fb8f } }
};

static void
compute_kG_448 (uint8_t *out, const uint8_t *k)
{
  int i, j;
  p448_t x0[1], y0[1], z0[1]; /* P0 */
  p448_t tmp0[1], tmp1[1];

  /* P0 <= O */
  memset (x0, 0, sizeof (p448_t));
  memset (y0, 0, sizeof (p448_t));
  memset (z0, 0, sizeof (p448_t));
  y0->limb[0] = 1;
  z0->limb[0] = 1;

  for (i = 0; i < 56*2; i++)
    {
      p448_t b[1], c[1], d[1];
      p448_t e[1], f[1], g[1], h[1];
      int index;

      for (j = 0; j < 4; j++)
	{
	  /* Point double P0' <= P0 + P0 */
	  p448_add (tmp0, x0, y0);
	  p448_sqr (b, tmp0);
	  p448_sqr (c, x0);
	  p448_sqr (d, y0);
	  p448_add (e, c, d);
	  p448_sqr (h, z0);
	  p448_add (tmp0, h, h);
	  p448_sub (tmp1, e, tmp0);
	  p448_sub (tmp0, b, e);
	  p448_mul (x0, tmp0, tmp1);
	  p448_sub (tmp0, c, d);
	  p448_mul (y0, e, tmp0);
	  p448_mul (z0, e, tmp1);
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
	}

      if ((i & 1) == 0)
	index = k[56 - (i/2) - 1] >> 4;
      else
	index = k[56 - (i/2) - 1] & 0xf;

      /* Point addition P0' <= P0 + [index]G */
      p448_sqr (b, z0);
      p448_mul (c, x0, &nGx[index]);
      p448_mul (d, y0, &nGy[index]);
      p448_mul (tmp0, c, d);
      p448_mul_39081 (e, tmp0);
      p448_add (f, b, e);
      p448_sub (g, b, e);
      p448_add (tmp0, x0, y0);
      p448_add (tmp1, &nGx[index], &nGy[index]);
      p448_mul (h, tmp0, tmp1);
      p448_sub (tmp0, h, c);
      p448_sub (tmp1, tmp0, d);
      p448_mul (tmp0, f, tmp1);
      p448_mul (x0, z0, tmp0);
      p448_sub (tmp0, d, c);
      p448_mul (tmp1, g, tmp0);
      p448_mul (y0, z0, tmp1);
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

  /* Convert to affine coordinate.  */
  p448_inv (tmp0, z0);
  p448_mul (tmp1, x0, tmp0);
  p448_serialize (out, tmp1);
  /* EdDSA encoding.  */
  out[56] = (out[0] & 1) << 7;
  p448_mul (tmp1, y0, tmp0);
  p448_serialize (out, tmp1);
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
