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
POLYVAL (const uint64_t H[2], const uint8_t *input, unsigned int len,
         uint64_t result[2])
{	
  uint64_t in[2];
  int i;
  int blocks = len/16;

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

  i = len - blocks * 16;
  if (i != 0)
    {
      int j;
      const uint8_t *p = &input[blocks*16];

      in[0] = 0;
      j = (i > 8)? 8: i;
      while (j)
        {
          in[0] = (in[0] << 8) | *p++;
          j--;
        }

      in[1] = 0;
      if (i > 8)
        {
          j = i - 8;
          while (j)
            {
              in[1] = (in[1] << 8) | *p++;
              j--;
            }
        }

      result[0] ^= in[0];
      result[1] ^= in[1];
      gfmul_mont (result, H, result);
    }
}

#include <string.h>
#include "aes.h"

#define DATA_ENCRYPTION_NONCE_SIZE 12
#define ENCRYPTION_BLOCK_SIZE      16
#define DATA_ENCRYPTION_KEY_SIZE   32
#define DATA_ENCRYPTION_TAG_SIZE   16
#define DATA_ENCRYPTION_AUTH64_SIZE 2 /* size in uint64_t */

#define CKDC_CALC  0
#define CKDC_CHECK 1
static int
compute_key_data_checksum (const uint64_t auth_key[DATA_ENCRYPTION_AUTH64_SIZE],
                           uint8_t encr_key[DATA_ENCRYPTION_KEY_SIZE],
			   const uint8_t *nonce,
			   const uint8_t *ad, unsigned int ad_len,
			   const uint8_t *data, unsigned int data_len,
			   uint8_t *checksum, int check_or_calc)
{
  aes_context aes;
  uint64_t tag[DATA_ENCRYPTION_AUTH64_SIZE];
  uint64_t lenblk[2];
  int i;
  uint8_t *p;

  tag[0] = tag[1] = 0;
  lenblk[0] = ad_len * 8;
  lenblk[1] = data_len * 8;
  POLYVAL (auth_key, ad, ad_len, tag);
  POLYVAL (auth_key, data, data_len, tag);
  POLYVAL (auth_key, (const uint8_t *)lenblk, sizeof lenblk, tag);
  /* XOR the TAG by NONCE. */
  p = (uint8_t *)tag;
  for (i = 0; i < DATA_ENCRYPTION_NONCE_SIZE; i++)
    p[i] ^= nonce[i];
  p[DATA_ENCRYPTION_TAG_SIZE - 1] &= 0x7f;

  aes_set_key (&aes, encr_key);

  if (check_or_calc == CKDC_CALC)	/* store */
    {
      aes_encrypt (&aes, (const unsigned char *)tag, checksum);
      aes_clear_key (&aes);
      return 0;
    }
  else				/* check */
    {
      aes_encrypt (&aes, (const unsigned char *)tag, (unsigned char *)tag);
      aes_clear_key (&aes);
      return memcmp (checksum, tag, DATA_ENCRYPTION_TAG_SIZE) == 0;
    }
}

static void
crypt0 (const uint8_t *key, uint8_t ctr_blk[ENCRYPTION_BLOCK_SIZE],
	uint8_t *data, unsigned int len)
{
  aes_context aes;

  aes_set_key (&aes, key);
  aes_ctr (&aes, ctr_blk, data, len, data);
  aes_clear_key (&aes);
}

static void
derive_keys (const uint8_t *key_generating_key, const uint8_t *nonce,
	     uint64_t auth_key[DATA_ENCRYPTION_AUTH64_SIZE],
	     uint8_t encr_key[DATA_ENCRYPTION_KEY_SIZE])
{
  aes_context aes;
  uint8_t blk0[ENCRYPTION_BLOCK_SIZE];
  uint8_t blk1[ENCRYPTION_BLOCK_SIZE];

  aes_set_key (&aes, key_generating_key);
  memset (blk0, 0, 4);
  memcpy (blk0+4, nonce, DATA_ENCRYPTION_NONCE_SIZE);
  aes_encrypt (&aes, blk0, blk1);
  memcpy (&auth_key[0], blk1, 8);
  blk0[0] = 1;
  aes_encrypt (&aes, blk0, blk1);
  memcpy (&auth_key[1], blk1, 8);
  blk0[0] = 2;
  aes_encrypt (&aes, blk0, blk1);
  memcpy (&encr_key[0], blk1, 8);
  blk0[0] = 3;
  aes_encrypt (&aes, blk0, blk1);
  memcpy (&encr_key[8], blk1, 8);
  blk0[0] = 4;
  aes_encrypt (&aes, blk0, blk1);
  memcpy (&encr_key[16], blk1, 8);
  blk0[0] = 5;
  aes_encrypt (&aes, blk0, blk1);
  memcpy (&encr_key[24], blk1, 8);
  aes_clear_key (&aes);
}

void
gcm_siv_encrypt (const uint8_t *key, const uint8_t *nonce,
                 const uint8_t *ad, int ad_len,
                 uint8_t *data, int data_len, uint8_t *tag)
{
  uint64_t auth_key[DATA_ENCRYPTION_AUTH64_SIZE];
  uint8_t encr_key[DATA_ENCRYPTION_KEY_SIZE];
  uint8_t ctr_blk[ENCRYPTION_BLOCK_SIZE];

  derive_keys (key, nonce, auth_key, encr_key);
  compute_key_data_checksum (auth_key, encr_key, nonce, ad, ad_len,
                             data, data_len, tag, CKDC_CALC);
  memcpy (ctr_blk, tag, ENCRYPTION_BLOCK_SIZE);
  ctr_blk[15] |= 0x80;
  crypt0 (encr_key, ctr_blk, data, data_len);
}

int
gcm_siv_decrypt (const uint8_t *key, const uint8_t *nonce,
                 const uint8_t *ad, int ad_len,
                 uint8_t *data, int data_len, uint8_t *tag)
{
  int r;
  uint64_t auth_key[DATA_ENCRYPTION_AUTH64_SIZE];
  uint8_t encr_key[DATA_ENCRYPTION_KEY_SIZE];
  uint8_t ctr_blk[ENCRYPTION_BLOCK_SIZE];

  derive_keys (key, nonce, auth_key, encr_key);
  memcpy (ctr_blk, tag, ENCRYPTION_BLOCK_SIZE);
  ctr_blk[15] |= 0x80;
  crypt0 (encr_key, ctr_blk, data, data_len);
  r = compute_key_data_checksum (auth_key, encr_key, nonce, ad, ad_len,
                                 data, data_len, tag, CKDC_CHECK);
  return r;
}
