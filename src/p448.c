/*                                                    -*- coding: utf-8 -*-
 * p448.c - Modular calculation with p448: 2^448 - 2^224 - 1
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
#include "p448.h"

#define MASK_28BITS 0x0fffffff

static void
p448_add_raw (p448_t *x, const p448_t *a, const p448_t *b)
{
  int i;

  for (i = 0; i < N_REDUNDANT_LIMBS; i++)
    x->limb[i] = a->limb[i] + b->limb[i];
}

static void
p448_sub_raw (p448_t *x, const p448_t *a, const p448_t *b)
{
  int i;

  for (i = 0; i < N_REDUNDANT_LIMBS; i++)
    x->limb[i] = a->limb[i] - b->limb[i];
}

static uint64_t
mul64_32x32 (const uint32_t a, const uint32_t b)
{
  return ((uint64_t)a) * b;
}

/**
 * Compute X = A * B mod p448
 */
/*
 * It's called "golden-ratio prime".
 *
 * When we set: phi = 2^224, Karatsuba multiplication goes like:
 *
 * (s + t * phi) * (u + v * phi)
 * =  su + (sv + tu)*phy + tv*phi^2
 * == (su + tv) + (sv + tu + tv) * phy (mod p448)
 * = (su + tv) + ((s + t)*(u + v) - su) * phy
 *
 * That is, it can be done by three times of 224-bit multiplications
 * (instead of four).
 *
 * Let us see more detail.
 *
 * The formula above is congruent to:
 * == lower224(su + tv) + upper224(su + tv)*phy
 *                      + lower224((s + t)*(u + v) - su)*phy
 *                      + upper224((s + t)*(u + v) - su)*phy^2 (mod p448)
 * == lower224(su + tv)
 *    + upper224((s + t)*(u + v) - su)
 *                      + (upper224(su + tv)
 *                         + lower224((s + t)*(u + v) - su)
 *                         + upper224((s + t)*(u + v) - su))*phy (mod p448)
 * = lower224(su + tv)
 *   + upper224((s + t)*(u + v) - su)
 *                      + (lower224((s + t)*(u + v) - su)
 *                         + upper224((s + t)*(u + v) + tv)) * phy
 *
 */
/*

Here is a figure of: multiplication by 8-limb * 8-limb

                      a  b  c  d  e  f  g  h
 *                    i  j  k  l  m  n  o  p
---------------------------------------------
                     ap bp cp dp ep fp gp hp
                  ao bo co do eo fo go ho
               an bn cn dn en fn gn hn
            am bm cm dm em fm gm hm
         al bl cl dl el fl gl hl
      ak bk ck dk ek fk gk hk
   aj bj cj dj ej fj gj hj
ai bi ci di ei fi gi hi

lower224
                     ap bp cp dp ep fp gp hp
                     bo co do eo fo go ho
                     cn dn en fn gn hn
                     dm em fm gm hm
                     el fl gl hl
                     fk gk hk
                     gj hj
                     hi

upper224
                                          ao
                                       an bn
                                    am bm cm
                                 al bl cl dl
                              ak bk ck dk ek
                           aj bj cj dj ej fj
                        ai bi ci di ei fi gi
*/
void
p448_mul (p448_t *__restrict__ x, const p448_t *a, const p448_t *b)
{
  int i, j;
  uint64_t var64_0, var64_1, var64_2;
  uint32_t s_t[8], u_v[8];
  uint32_t *px;
  const uint32_t *pa, *pb;

  px = x->limb;
  pa = a->limb;
  pb = b->limb;

  /* Firstly, we do Karatsuba preparation.  */
  for (i = 0; i < 8; i++)
    {
      s_t[i] = pa[i] + pa[i+8];
      u_v[i] = pb[i] + pb[i+8];
    }

  var64_0 = var64_1 = 0;

  for (j = 0; j < 8; j++)
    {
      var64_2 = 0;

      /* Compute lower half of limbs (lower224) */
      /*  __  <-- j
       * | /        |
       * |/         v i
       *
       */
      for (i = 0; i <= j; i++)
	{
	  var64_0 += mul64_32x32 (pa[8+j-i], pb[8+i]);/* accumulating t*v */
	  var64_1 += mul64_32x32 (s_t[j-i], u_v[i]);  /* accumulating s_t*u_v */
	  var64_2 += mul64_32x32 (pa[j-i], pb[i]);    /* accumulating s*u */
	}

      var64_0 += var64_2; /* Compute su+tv.         */
      var64_1 -= var64_2; /* Compute s_t*u_v - su.  */

      var64_2 = 0;

      /* Compute upper half of limbs (upper224) */
      /*     <-- j
       *  /|        |
       * /_|        v i
       *
       */
      for (; i < 8; i++)
	{
	  var64_0 -= mul64_32x32 (pa[8+j-i], pb[i]);   /* accumulating -s*u */
	  var64_1 += mul64_32x32 (pa[16+j-i], pb[8+i]);/* accumulating t*v */
	  var64_2 += mul64_32x32 (s_t[8+j-i], u_v[i]);/* accumulating s_t*u_v */
	}

      var64_0 += var64_2; /* Compute s_t*u_v - su.  */
      var64_1 += var64_2; /* Compute s_t*u_v + tv.  */

      px[j] = var64_0 & MASK_28BITS;
      px[j+8] = var64_1 & MASK_28BITS;

      var64_0 >>= 28;
      var64_1 >>= 28;
    }

  /* "Carry" remains as: 2^448 * var64_1 + 2^224 * var64_0 */
  /*
   * Subtract p448 times var64_1 to clear msbs, meaning, clear those
   * bits and adding var64_1 to px[0] and px[8] (in mod p448
   * calculation).
   */
  var64_0 += var64_1;
  var64_0 += px[8];
  var64_1 += px[0];
  px[8] = var64_0 & MASK_28BITS;
  px[0] = var64_1 & MASK_28BITS;

  /* Still, it carries to... */
  var64_0 >>= 28;
  var64_1 >>= 28;
  px[9] += var64_0;
  px[1] += var64_1;
  /* DONE.  */
}


/**
 * Compute X = A * 39081
 */
void
p448_mul_39081 (p448_t *__restrict__ x, const p448_t *a)
{
  int i;
  const uint32_t w = 39081;
  uint32_t *px;
  const uint32_t *pa;
  uint64_t v64;
  uint32_t carry;

  px = x->limb;
  pa = a->limb;

  v64 = 0;
  for (i = 0; i < N_REDUNDANT_LIMBS; i++)
    {
      v64 += mul64_32x32 (w, pa[i]);
      px[i] = v64 & MASK_28BITS;
      v64 >>= 28;
    }

  carry = v64;
  carry += px[0];
  px[0] = carry & MASK_28BITS;
  px[1] += carry >> 28;

  carry = v64;
  carry += px[8];
  px[8] = carry & MASK_28BITS;
  px[9] += carry >> 28;
}

/**
 * Compute X = A^2 mod p448
 */
void
p448_sqr (p448_t *__restrict__ x, const p448_t *a)
{
  p448_mul (x, a, a);
}

/**
 * Weak reduce - Make each limb of redundunt representation smaller.
 * Do our best weakly to zeroing most significant 4-bit.
 *
 * Note that: p448 = 2^448 - 2^224 - 1
 *
 * Subtracting p448 means that subtracting 2^448 then adding 2^224 + 1.
 */
void
p448_weak_reduce (p448_t *a)
{
  int i;
  uint32_t tmp = a->limb[15] >> 28;

  a->limb[8] += tmp;  /* Adding TMP * 2^224 (28 * 8 = 224) */

  /* Compute top to bottom.  */
  for (i = 0; i < N_REDUNDANT_LIMBS - 1; i++)
    a->limb[N_REDUNDANT_LIMBS - i - 1] =
      (a->limb[N_REDUNDANT_LIMBS - i - 1] & MASK_28BITS)
      + (a->limb[N_REDUNDANT_LIMBS - i - 2] >> 28);

  a->limb[0] = (a->limb[0] & MASK_28BITS) + tmp;
}

static p448_t p448[1] = {
  0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff,
  0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff,
  0x0ffffffe, 0x0fffffff, 0x0fffffff, 0x0fffffff,
  0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff,
};


static uint32_t
p448_add_carry_cond (p448_t *x, const p448_t *a, const p448_t *b,
		     uint32_t cond)
{
  int i;
  uint32_t v;
  uint32_t carry = 0;
  uint32_t *px;
  const uint32_t *pa, *pb;

  cond = cond * MASK_28BITS;

  px = x->limb;
  pa = a->limb;
  pb = b->limb;

  for (i = 0; i < N_REDUNDANT_LIMBS; i++)
    {
      v = *pb & cond;
      *px = *pa + carry;
      carry = (*px < carry);
      *px = (*px + v) & MASK_28BITS;
      carry += (*px < v);
      px++;
      pa++;
      pb++;
    }

  return carry;
}


static uint32_t
p448_sub_borrow (p448_t *x, const p448_t *a, const p448_t *b)
{
  int i;
  uint32_t v;
  uint32_t borrow = 0;
  uint32_t *px;
  const uint32_t *pa, *pb;

  px = x->limb;
  pa = a->limb;
  pb = b->limb;

  for (i = 0; i < N_REDUNDANT_LIMBS; i++)
    {
      uint32_t borrow0 = (*pa < borrow);

      v = *pb;
      *px = *pa - borrow;
      borrow = (*px < v) + borrow0;
      *px = (*px - v) & MASK_28BITS;
      px++;
      pa++;
      pb++;
    }

  return borrow;
}

/**
 * Strong reduce - Make sure that each limb of redundunt
 * representation has zeros of significant 4-bit.
 */
void
p448_strong_reduce (p448_t *a)
{
  int i;
  uint32_t tmp;
  uint32_t is_negative;

  /*
   * Clear the 4-bit of the last (top) limb.  As stated in the comment
   * of weak_reduce, subtracting p448 means that subtracting 2^448
   * then adding 2^224 + 1.
   */
  tmp = a->limb[15] >> 28;
  a->limb[8] += tmp;
  a->limb[0] += tmp;
  a->limb[15] &= MASK_28BITS;

  /*
   * p448 can be represented in redundant representation:
   *  0{4}1{28}  0{4}1{28} 0{4}1{28} 0{4}1{28}
   *  0{4}1{28}  0{4}1{28} 0{4}1{28} 0{4}1{28}
   *  0{4}1{27}0 0{4}1{28} 0{4}1{28} 0{4}1{28}
   *  0{4}1{28}  0{4}1{28} 0{4}1{28} 0{4}1{28}
   *
   * So, 2*p448 can be represented:
   *  0{4}1{27}0  0{4}1{28} 0{4}1{28} 0{4}1{28}
   *  0{4}1{28}   0{4}1{28} 0{4}1{28} 0{4}1{28}
   *  0{4}1{26}01 0{4}1{28} 0{4}1{28} 0{4}1{28}
   *  0{4}1{28}   0{4}1{28} 0{4}1{28} 0{3}1{29}
   *
   * Suppose that each limb has 31 of 1s in A (maximum), when called.
   *
   *  01{31}    01{31} 01{31} 01{31} 01{31} 01{31} 01{31} 01{31}
   *  01{31}    01{31} 01{31} 01{31} 01{31} 01{31} 01{31} 01{31}
   *
   * Here, cleared the 4-bit of the last limb above, it becomes:
   *  10{28}110 01{31} 01{31} 01{31} 01{31} 01{31} 01{31} 01{31}
   *  10{28}110 01{31} 01{31} 01{31} 01{31} 01{31} 01{31} 0{4}1{28}
   *
   * When trying to clear 4-bit of all limbs of these, it can be reduced as:
   *  0{3}10{25}110 0{3}10{25}110 0{3}10{25}110 0{3}10{25}110
   *  0{3}10{25}110 0{3}10{25}110 0{3}10{25}110 0{3}10{25}110
   *  0{28}1101 0{3}10{25}111 0{3}10{25}110 0{3}10{25}110
   *  0{3}10{25}110 0{3}10{25}110 0{3}10{25}110 0{3}10{25}110
   * then, clear 4-bit of all limbs (other than the last one),
   * it can be reduced as:
   *  0{29}110  0{29}111 0{29}111 0{29}111
   *  0{29}111  0{29}111 0{29}111 0{29}111
   *  0{28}1110 0{29}111 0{29}111 0{29}111
   *  0{29}111  0{29}111 0{29}111 0{3}10{25}111
   *
   * Comparing this to the representation of 2*p448, it is guaranteed that
   * the value represented here must be less than 2*p448.
   *
   * So, it's: 0 < v < 2*p448
   *
   * When v > p448, subtract p448 from v, then it becomes strongly reduced.
   * Otherwise, it's already strongly reduced.
   *
   */

  /* Subtract p448 */
  is_negative = p448_sub_borrow (a, a, p448);

  /* Add p448 conditionally, when it becomes negative.  */
  p448_add_carry_cond (a, a, p448, is_negative);
}

/**
 * Convert to wire-format from internal redundant representation.
 */
void
p448_serialize (uint8_t serial[56], const struct p448_t *x)
{
  int i;
  p448_t tmp[1];
  uint8_t *p = serial;

  *tmp = *x;
  p448_strong_reduce (tmp);

  for (i = 0; i < 8; i++)
    {
      uint32_t limb0 = tmp->limb[2*i];
      uint32_t limb1 = tmp->limb[2*i+1];

      *p++ = limb0;
      *p++ = (limb0 >> 8);
      *p++ = (limb0 >> 16);
      *p++ = ((limb0 >> 24) & 0x0f) | ((limb1 & 0x0f )<< 4);
      *p++ = (limb1 >> 4);
      *p++ = (limb1 >> 12);
      *p++ = (limb1 >> 20);
    }
}

/**
 * Convert from wire-format to internal redundant representation.
 */
void
p448_deserialize (p448_t *x, const uint8_t serial[56])
{
  int i;
  const uint8_t *p = serial + 56;

  for (i = 0; i < 8; i++)
    {
      uint32_t v;

      v = *--p;
      v <<= 8;
      v |= *--p;
      v <<= 8;
      v |= *--p;
      v <<= 8;
      v |= *--p;

      x->limb[N_REDUNDANT_LIMBS-2*i-1] = v & MASK_28BITS;

      v >>= 28;
      v <<= 8;
      v |= *--p;
      v <<= 8;
      v |= *--p;
      v <<= 8;
      v |= *--p;

      x->limb[N_REDUNDANT_LIMBS-2*i-2] = v & MASK_28BITS;
    }
}


/* X = A^(2*N) */
static void
p448_sqrn (p448_t *__restrict__ x, const p448_t *a, int n)
{
  p448_t tmp[1];

  if ((n&1))
    {
      p448_sqr (x, a);
      n--;
    }
  else
    {
      p448_sqr (tmp, a);
      p448_sqr (x, tmp);
      n -= 2;
    }

  for (; n; n -= 2)
    {
      p448_sqr (tmp, x);
      p448_sqr (x, tmp);
    }
}

/**
 * Compute X = A^(-1) mod p448 (if A=0, return X = 0)
 *
 * Internally, do A^(p448 - 2) to get A^(-1).
 */
void
p448_inv (p448_t *__restrict__ x, const p448_t *a)
{
  p448_t  t[1],  u[1];

  /*
   * Bit pattern of p448-2: 1{223} 0 1{222}01
   *
   * 222-bit can be composed by 3-bit three times to get 9-bit, 9-bit
   * two times to get 18-bit, 18-bit two times plus 1-bit to get 37-bit.
   * 37-bit three times to get 111-bit, and lastly 111-bit two times.
   *   222 = 111*2 = 37*3*2 = (18*2+1)*3*2 = (9*2*2+1)*3*2 = (3*3*2*2+1)*3*2
   */
  p448_sqr  ( x, a      );  /*        10 */
  p448_mul  ( t, a, x   );  /*        11 */
  p448_sqr  ( x, t      );  /*       110 */
  p448_mul  ( t, a, x   );  /*       111 */
  p448_sqrn ( x, t, 3   );  /*    111000 */
  p448_mul  ( u, t, x   );  /*    111111 */
  p448_sqrn ( x, u, 3   );  /* 111111000 */
  p448_mul  ( u, t, x   );  /* 111111111 */
  p448_sqrn ( t, u, 9   );  /* 1{9} 0{9}         */
  p448_mul  ( x, u, t   );  /* 1{18}             */
  p448_sqr  ( t, x      );  /* 1{18} 0           */
  p448_mul  ( u, a, t   );  /* 1{19}             */
  p448_sqrn ( t, u, 18  );  /* 1{19} 0{18}       */
  p448_mul  ( u, x, t   );  /* 1{37}             */
  p448_sqrn ( t, u, 37  );  /* 1{37} 0{37}       */
  p448_mul  ( x, u, t   );  /* 1{74}             */
  p448_sqrn ( t, x, 37  );  /* 1{74} 0{37}       */
  p448_mul  ( x, u, t   );  /* 1{111}            */
  p448_sqrn ( t, x, 111 );  /* 1{111} 0{111}     */
  p448_mul  ( u, x, t   );  /* 1{222}            */
  p448_sqr  ( t, u      );  /* 1{222} 0          */
  p448_mul  ( x, a, t   );  /* 1{223}            */
  p448_sqrn ( u, x, 224 );  /* 1{223} 0{224}     */
  p448_mul  ( x, u, t   );  /* 1{223} 0 1{222}0  */
  p448_sqr  ( t, x      );  /* 1{223} 0 1{222}00 */
  p448_mul  ( x, a,  t  );  /* 1{223} 0 1{222}01 */
}

static p448_t p448_times_2[1] = {
  0x1ffffffe, 0x1ffffffe, 0x1ffffffe, 0x1ffffffe,
  0x1ffffffe, 0x1ffffffe, 0x1ffffffe, 0x1ffffffe,
  0x1ffffffc, 0x1ffffffe, 0x1ffffffe, 0x1ffffffe,
  0x1ffffffe, 0x1ffffffe, 0x1ffffffe, 0x1ffffffe,
};

/**
 * Compute X = A + B mod p448, result is weakly reduced.
 *
 */
void
p448_add (p448_t *x, const p448_t *a, const p448_t *b)
{
  p448_add_raw (x, a, b);
  p448_weak_reduce (x);
}

/**
 * Compute X = A - B mod p448, result is weakly reduced.
 *
 */
void
p448_sub (p448_t *x, const p448_t *a, const p448_t *b)
{
  p448_t tmp[1];

  p448_sub_raw (tmp, a, b);
  p448_add_raw (x, p448_times_2, tmp);
  p448_weak_reduce (x);
}
