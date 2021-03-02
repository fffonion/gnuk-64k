/*                                                    -*- coding: utf-8 -*-
 * ecc-x448.c - Elliptic curve computation for
 *              the Montgomery curve: y^2 = x^3 + 156326*x^2 + x
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

#define N_REDUNDANT_LIMBS 16
#define N_LIMBS 14

typedef struct p448_t {
  uint32_t limb[N_REDUNDANT_LIMBS];
} p448_t;

typedef struct
{
  p448_t x[1];
  p448_t z[1];
} pt;


extern void p448_add (p448_t *x, const p448_t *a, const p448_t *b);
extern void p448_sub (p448_t *x, const p448_t *a, const p448_t *b);
extern void p448_mul (p448_t *__restrict__ x, const p448_t *a, const p448_t *b);
extern void p448_mul_int (p448_t *__restrict__ x, const p448_t *a, int32_t b);
extern void p448_sqr (p448_t *__restrict__ c, const p448_t *a);
extern void p448_inv (p448_t *__restrict__ x, const p448_t *a);
extern void p448_serialize (uint8_t serial[56], const p448_t *x);
extern int p448_deserialize (p448_t *x, const uint8_t serial[56]);

/**
 * @brief  Process Montgomery double-and-add
 *
 * With Q0, Q1, DIF (= Q0 - Q1), compute PRD = 2Q0, SUM = Q0 + Q1
 * Q0 and Q1 are clobbered.
 *
 */
static void
mont_d_and_a (pt *prd, pt *sum, pt *q0, pt *q1, const p448_t dif_x[1])
{
  p448_t q1__z[1];
  p448_t q0__z[1];
  p448_t sum__x[1];
#define sum__z q1__z
#define prd__z q1__z
                                        p448_add (sum->x, q1->x, q1->z);
                                        p448_sub (q1->z, q1->x, q1->z);
  p448_add (prd->x, q0->x, q0->z);
  p448_sub (q0->z, q0->x, q0->z);
                                        p448_mul (q1->x, q0->z, sum->x);
                                        p448_mul (q1__z, prd->x, q1->z);
  p448_sqr (q0->x, prd->x);
  p448_sqr (q0__z, q0->z);
                                        p448_add (sum__x, q1->x, q1__z);
                                        p448_sub (q1->z, q1->x, q1__z);
  p448_mul (prd->x, q0->x, q0__z);
  p448_sub (q0->z, q0->x, q0__z);
                                        p448_sqr (sum->x, sum__x);
                                        p448_sqr (sum__z, q1->z);
  p448_mul_int (prd->z, q0->z, 39081);
                                        p448_mul (sum->z, sum__z, dif_x);
  p448_add (prd__z, q0->x, prd->z);
  p448_mul (prd->z, prd__z, q0->z);
}


/**
 * @brief	RES  = x-coordinate of [n]Q
 *
 * @param N	Scalar N (three least significant bits are 00)
 * @param Q_X	x-coordinate of Q
 *
 */
static void
compute_nQ (uint8_t *res, const uint32_t n[N_LIMBS], const p448_t q_x[1])
{
  int i, j;
  pt p0[1], p1[1], p0_[1], p1_[1];
#define tmp0 p0->z
#define tmp1 p1->z

  /* P0 = O = (1:0)  */
  memset (p0->x, 0, sizeof (p0->x));
  p0->x->limb[0] = 1;
  memset (p0->z, 0, sizeof (p0->z));

  /* P1 = (X:1) */
  memcpy (p1->x, q_x, N_REDUNDANT_LIMBS*4);
  memset (p1->z, 0, sizeof (p1->z));
  p1->z->limb[0] = 1;

  for (i = 0; i < N_LIMBS; i++)
    {
      uint32_t u = n[N_LIMBS-i-1];

      for (j = 0; j < 16; j++)
	{
	  pt *q0, *q1;
	  pt *sum_n, *prd_n;

	  if ((u & 0x80000000))
	    q0 = p1,  q1 = p0,  sum_n = p0_, prd_n = p1_;
	  else
	    q0 = p0,  q1 = p1,  sum_n = p1_, prd_n = p0_;
	  mont_d_and_a (prd_n, sum_n, q0, q1, q_x);

	  if ((u & 0x40000000))
	    q0 = p1_, q1 = p0_, sum_n = p0,  prd_n = p1;
	  else
	    q0 = p0_, q1 = p1_, sum_n = p1,  prd_n = p0;
	  mont_d_and_a (prd_n, sum_n, q0, q1, q_x);

	  u <<= 2;
	}
    }

  /* We know the LSB of N is always 0.  Thus, result is always in P0.  */
  /*
   * p0->z may be zero here, but our inverse function doesn't raise
   * error for 0, but returns 0, thus, RES will be 0 in that case,
   * which is correct value.
   */
  p448_inv (tmp1, p0->z);
  p448_mul (tmp0, tmp1, p0->x);
  p448_serialize (res, tmp0);
}


void
ecdh_compute_public_448 (const uint8_t *key_data, uint8_t *pubkey)
{
  p448_t gx[1] = { 5, };
  uint32_t k[N_LIMBS];

  memcpy (k, key_data, N_LIMBS*4);
  k[0] &= ~3;
  k[N_LIMBS-1] |= 0x80000000;
  compute_nQ (pubkey, k, gx);
}

int
ecdh_decrypt_curve448 (const uint8_t *input, uint8_t *output,
		       const uint8_t *key_data)
{
  p448_t q_x[1];
  uint32_t k[N_LIMBS];

  p448_deserialize (q_x, input);
  memcpy (k, key_data, N_LIMBS*4);
  k[0] &= ~3;
  k[N_LIMBS-1] |= 0x80000000;
  compute_nQ (output, k, q_x);
  return 0;
}
