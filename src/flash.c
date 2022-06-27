/*
 * flash.c -- Data Objects (DO) and GPG Key handling on Flash ROM
 *
 * Copyright (C) 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017, 2018,
 *               2022
 *               Free Software Initiative of Japan
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

/*
 * We assume single DO size is less than 256.
 *
 * NOTE: "Card holder certificate" (which size is larger than 256) is
 *       not put into data pool, but is implemented by its own flash
 *       page(s).
 */

#include <stdint.h>
#include <string.h>

#include "config.h"

#include "sys.h"
#include "gnuk.h"

/*
 * Flash memory map
 *
 * _text
 *         .text
 *         .ctors
 *         .dtors
 * _etext
 *         .data
 * _bss_start
 *         .bss
 * _end
 *         <alignment to page>
 * ch_certificate_startp
 *         <2048 bytes>
 * _keystore_pool
 *         Three flash pages for keystore
 *         a page contains a key data of:
 *              For ECDSA/ECDH and EdDSA, there are padding after public key
 * _data_pool
 *	   <two pages>
 */

#define FLASH_DATA_POOL_HEADER_SIZE	2
#define FLASH_DATA_POOL_SIZE		(flash_page_size*2)

static uint16_t flash_page_size;
static const uint8_t *data_pool;
static uint8_t *last_p;

/* The first halfword is generation for the data page (little endian) */
const uint8_t flash_data[4] __attribute__ ((section (".gnuk_data"))) = {
  0x00, 0x00, 0xff, 0xff
};

#ifdef GNU_LINUX_EMULATION
extern uint8_t *flash_addr_key_storage_start;
extern uint8_t *flash_addr_data_storage_start;
#define FLASH_ADDR_KEY_STORAGE_START  flash_addr_key_storage_start
#define FLASH_ADDR_DATA_STORAGE_START flash_addr_data_storage_start
#else
/* Linker sets these symbols */
extern uint8_t _keystore_pool[];
extern uint8_t _data_pool[];
#define FLASH_ADDR_KEY_STORAGE_START  ((_keystore_pool))
#define FLASH_ADDR_DATA_STORAGE_START ((_data_pool))
#endif

#define MAX_PKC_KEY 3

#define FLASH_PKC_TAG_ZERO 0x00
#define FLASH_PKC_TAG_KEY  0x10 /* 0x10...0x70: (ALGO_* << 4) */
#define FLASH_PKC_TAG_DEK  0x80 /* 0x80...0xA0 */
#define FLASH_PKC_TAG_NONE 0xF0

#define FLASH_PKC_TAG_MASK 0xF0
#define FLASH_PKC_TAG_KEY_BIT  0x80
#define FLASH_PKC_TAG_KEY_ALGO 0x70
#define FLASH_PKC_TAG_DEK0 0x80
#define FLASH_PKC_TAG_DEK1 0x90
#define FLASH_PKC_TAG_DEK2 0xA0


struct pkc_key {
  const uint8_t *key_addr;
  uint16_t dek_offset[3];
  uint16_t last_dek_offset;
};

struct pkc_key pkc_key[MAX_PKC_KEY];


#define CHIP_ID_REG      ((uint32_t *)0xe0042000)
void
flash_do_storage_init (const uint8_t **p_do_start, const uint8_t **p_do_end)
{
  uint16_t gen0, gen1;
  uint16_t *gen0_p = (uint16_t *)FLASH_ADDR_DATA_STORAGE_START;
  uint16_t *gen1_p;

  flash_page_size = 1024;
#if !defined (GNU_LINUX_EMULATION)
  if (((*CHIP_ID_REG) & 0xfff) == 0x0414)
    flash_page_size = 2048;
#endif

  gen1_p = (uint16_t *)(FLASH_ADDR_DATA_STORAGE_START + flash_page_size);
  data_pool = FLASH_ADDR_DATA_STORAGE_START;

  /* Check data pool generation and choose the page */
  gen0 = *gen0_p;
  gen1 = *gen1_p;

  if (gen0 == 0xffff && gen1 == 0xffff)
    {
      /* It's terminated.  */
      *p_do_start = *p_do_end = NULL;
      return;
    }

  if (gen0 == 0xffff)
    /* Use another page if a page is erased.  */
    data_pool = FLASH_ADDR_DATA_STORAGE_START + flash_page_size;
  else if (gen1 == 0xffff)
    /* Or use different page if another page is erased.  */
    data_pool = FLASH_ADDR_DATA_STORAGE_START;
  else if ((gen0 == 0xfffe && gen1 == 0) || gen1 > gen0)
    /* When both pages have valid header, use newer page.   */
    data_pool = FLASH_ADDR_DATA_STORAGE_START + flash_page_size;

  *p_do_start = data_pool + FLASH_DATA_POOL_HEADER_SIZE;
  *p_do_end = data_pool + flash_page_size;
}

static uint8_t *flash_key_getpage (enum kind_of_key kk);
static void flash_key_dek_scan (enum kind_of_key kk, const uint8_t *key_addr);

void
flash_terminate (void)
{
  int i;

  for (i = 0; i < MAX_PKC_KEY; i++)
    flash_key_release (i);
  flash_erase_page ((uintptr_t)FLASH_ADDR_DATA_STORAGE_START);
  flash_erase_page ((uintptr_t)(FLASH_ADDR_DATA_STORAGE_START + flash_page_size));
  data_pool = FLASH_ADDR_DATA_STORAGE_START;
  last_p = FLASH_ADDR_DATA_STORAGE_START + FLASH_DATA_POOL_HEADER_SIZE;
#if defined(CERTDO_SUPPORT)
  flash_erase_page ((uintptr_t)&ch_certificate_start);
  if (FLASH_CH_CERTIFICATE_SIZE > flash_page_size)
    flash_erase_page ((uintptr_t)(&ch_certificate_start + flash_page_size));
#endif
}

void
flash_activate (void)
{
  flash_program_halfword ((uintptr_t)FLASH_ADDR_DATA_STORAGE_START, 0);
}


void
flash_key_storage_init (void)
{
  const uint8_t *p;
  int i;

  /* For each key, find its address.  */
  p = FLASH_ADDR_KEY_STORAGE_START;
  for (i = 0; i < MAX_PKC_KEY; i++)
    {
      uint8_t tag;
      uint8_t b0 = *p;

      tag = (b0 & FLASH_PKC_TAG_MASK);
      if (tag != FLASH_PKC_TAG_NONE)
	{
	  pkc_key[i].key_addr = p;
	  flash_key_dek_scan (i, p);
	}

      p += flash_page_size;
    }
}

/*
 * Flash data pool managenent
 *
 * Flash data pool consists of two parts:
 *   2-byte header
 *   contents
 *
 * Flash data pool objects:
 *   Data Object (DO) (of smart card)
 *   Internal objects:
 *     NONE (0x0000)
 *     123-counter
 *     14-bit counter
 *     bool object
 *     small enum
 *
 * Format of a Data Object:
 *    NR:   8-bit tag_number
 *    LEN:  8-bit length
 *    DATA: data * LEN
 *    PAD:  optional byte for 16-bit alignment
 */

void
flash_set_data_pool_last (const uint8_t *p)
{
  last_p = (uint8_t *)p;
}

/*
 * We use two pages
 */
static int
flash_copying_gc (void)
{
  uint8_t *src, *dst;
  uint16_t generation;

  if (data_pool == FLASH_ADDR_DATA_STORAGE_START)
    {
      src = FLASH_ADDR_DATA_STORAGE_START;
      dst = FLASH_ADDR_DATA_STORAGE_START + flash_page_size;
    }
  else
    {
      src = FLASH_ADDR_DATA_STORAGE_START + flash_page_size;
      dst = FLASH_ADDR_DATA_STORAGE_START;
    }

  generation = *(uint16_t *)src;
  data_pool = dst;
  gpg_data_copy (data_pool + FLASH_DATA_POOL_HEADER_SIZE);
  if (generation == 0xfffe)
    generation = 0;
  else
    generation++;
  flash_program_halfword ((uintptr_t)dst, generation);
  flash_erase_page ((uintptr_t)src);
  return 0;
}

static int
is_data_pool_full (size_t size)
{
  return last_p + size > data_pool + flash_page_size;
}

static uint8_t *
flash_data_pool_allocate (size_t size)
{
  uint8_t *p;

  size = (size + 1) & ~1;	/* allocation unit is 1-halfword (2-byte) */

  if (is_data_pool_full (size))
    if (flash_copying_gc () < 0 || /*still*/ is_data_pool_full (size))
      fatal (FATAL_FLASH);

  p = last_p;
  last_p += size;
  return p;
}

void
flash_do_write_internal (const uint8_t *p, int nr, const uint8_t *data, int len)
{
  uint16_t hw;
  uintptr_t addr;
  int i;

  addr = (uintptr_t)p;
  hw = nr | (len << 8);
  if (flash_program_halfword (addr, hw) != 0)
    flash_warning ("DO WRITE ERROR");
  addr += 2;

  for (i = 0; i < len/2; i++)
    {
      hw = data[i*2] | (data[i*2+1]<<8);
      if (flash_program_halfword (addr, hw) != 0)
	flash_warning ("DO WRITE ERROR");
      addr += 2;
    }

  if ((len & 1))
    {
      hw = data[i*2] | 0xff00;
      if (flash_program_halfword (addr, hw) != 0)
	flash_warning ("DO WRITE ERROR");
    }
}

const uint8_t *
flash_do_write (uint8_t nr, const uint8_t *data, int len)
{
  const uint8_t *p;

  DEBUG_INFO ("flash DO\r\n");

  p = flash_data_pool_allocate (2 + len);
  if (p == NULL)
    {
      DEBUG_INFO ("flash data pool allocation failure.\r\n");
      return NULL;
    }

  flash_do_write_internal (p, nr, data, len);
  DEBUG_INFO ("flash DO...done\r\n");
  return p + 1;
}

void
flash_warning (const char *msg)
{
  (void)msg;
  DEBUG_INFO ("FLASH: ");
  DEBUG_INFO (msg);
  DEBUG_INFO ("\r\n");
}

void
flash_do_release (const uint8_t *do_data)
{
  uintptr_t addr = (uintptr_t)do_data - 1;
  uintptr_t addr_tag = addr;
  int i;
  int len = do_data[0];

  /* Don't filling zero for data in code (such as ds_count_initial_value) */
  if (do_data < FLASH_ADDR_DATA_STORAGE_START
      || do_data > FLASH_ADDR_DATA_STORAGE_START + FLASH_DATA_POOL_SIZE)
    return;

  addr += 2;

  /* Fill zero for content and pad */
  for (i = 0; i < len/2; i++)
    {
      if (flash_program_halfword (addr, 0) != 0)
	flash_warning ("fill-zero failure");
      addr += 2;
    }

  if ((len & 1))
    {
      if (flash_program_halfword (addr, 0) != 0)
	flash_warning ("fill-zero pad failure");
    }

  /* Fill 0x0000 for "tag_number and length" word */
  if (flash_program_halfword (addr_tag, 0) != 0)
    flash_warning ("fill-zero tag_nr failure");
}


static uint8_t *
flash_key_getpage (enum kind_of_key kk)
{
  /* There is a page for each KK.  */
  return FLASH_ADDR_KEY_STORAGE_START + (flash_page_size * kk);
}

const uint8_t *
flash_key_addr (enum kind_of_key kk,
                const uint8_t **nonce_p, const uint8_t **tag_p,
                const uint8_t **prvkey_p, int *prvkey_len_p,
                const uint8_t **pubkey_p, int *pubkey_len_p)
{
  const uint8_t *key_addr = pkc_key[kk].key_addr;

  if (key_addr)
    {
      const uint8_t *addr = key_addr;
      int algo;
      int prvkey_len;
      int pubkey_len;

      algo = (*addr) >> 4;
      addr += 2;
      prvkey_len = gpg_get_algo_key_size (algo, GPG_KEY_PRIVATE);
      pubkey_len = gpg_get_algo_key_size (algo, GPG_KEY_PUBLIC);
      if (nonce_p)
        *nonce_p = addr;
      addr += DATA_ENCRYPTION_NONCE_SIZE;
      if (tag_p)
        *tag_p = addr;
      addr += DATA_ENCRYPTION_TAG_SIZE;
      if (prvkey_p)
        *prvkey_p = addr;
      if (prvkey_len_p)
        *prvkey_len_p = prvkey_len;
      addr += prvkey_len;
      if (pubkey_p)
        *pubkey_p = addr;
      if (pubkey_len_p)
        *pubkey_len_p = pubkey_len;
    }
  else
    {
      if (nonce_p)
        *nonce_p = NULL;
      if (tag_p)
        *tag_p = NULL;
      if (prvkey_p)
        *prvkey_p = NULL;
      if (pubkey_p)
        *pubkey_p = NULL;
    }

  return key_addr + 2;
}

int
flash_key_write (enum kind_of_key kk, int algo,
                 const uint8_t *nonce, const uint8_t *tag,
		 const uint8_t *prvkey, int prvkey_len,
		 const uint8_t *pubkey, int pubkey_len)
{
  uint16_t hw;
  uintptr_t addr;
  int i;
  uint8_t *key_addr = flash_key_getpage (kk);
  uint16_t len = DATA_ENCRYPTION_NONCE_SIZE + DATA_ENCRYPTION_TAG_SIZE
    + prvkey_len + pubkey_len;

  addr = (uintptr_t)key_addr;
  pkc_key[kk].key_addr = key_addr;

  hw = ((algo << 4) | ((len >> 8) & 0x0f)) | ((len & 0xff) << 8);
  if (flash_program_halfword (addr, hw) != 0)
    return -1;
  addr += 2;

  for (i = 0; i < DATA_ENCRYPTION_NONCE_SIZE/2; i++)
    {
      hw = nonce[i*2] | (nonce[i*2+1]<<8);
      if (flash_program_halfword (addr, hw) != 0)
	return -1;
      addr += 2;
    }

  for (i = 0; i < DATA_ENCRYPTION_TAG_SIZE/2; i++)
    {
      hw = tag[i*2] | (tag[i*2+1]<<8);
      if (flash_program_halfword (addr, hw) != 0)
	return -1;
      addr += 2;
    }

  while (prvkey_len >= 2)
    {
      hw = *prvkey++;
      hw |= ((*prvkey++) << 8);
      prvkey_len -= 2;
      if (flash_program_halfword (addr, hw) != 0)
	return -1;
      addr += 2;
    }

  if (prvkey_len)
    {
      hw = *prvkey++;
      prvkey_len--;
      if (pubkey_len)
	{
	  hw |= *pubkey++;
	  pubkey_len--;
	}
      if (flash_program_halfword (addr, hw) != 0)
	return -1;
      addr += 2;
    }

  while (pubkey_len >= 2)
    {
      hw = *pubkey++;
      hw |= ((*pubkey++) << 8);
      pubkey_len -= 2;
      if (flash_program_halfword (addr, hw) != 0)
	return -1;
      addr += 2;
    }

  if (pubkey_len)
    {
      hw = *pubkey++;
      pubkey_len--;
      if (flash_program_halfword (addr, hw) != 0)
	return -1;
      addr += 2;
    }

  pkc_key[kk].last_dek_offset = addr - (uintptr_t)key_addr;

  return 0;
}

void
flash_key_release (enum kind_of_key kk)
{
  pkc_key[kk].key_addr = NULL;
  flash_erase_page ((uintptr_t)flash_key_getpage (kk));
}

static void
flash_key_dek_scan (enum kind_of_key kk, const uint8_t *key_addr)
{
  uint32_t len;
  const uint8_t *p;
  int dek_no;

  p = key_addr;
  len = ((key_addr[0] & 0x0f << 8) | key_addr[1]) + 2;

  while (p < key_addr + flash_page_size)
    {
      p += len;

      if (p[0] == 0xff)
	break;

      dek_no = (p[0] & 0x7) >> 4;
      len = p[1] + 2;
      pkc_key[kk].dek_offset[dek_no] = p - key_addr;
    }

  pkc_key[kk].last_dek_offset = p - key_addr;
}

static int
flash_key_garbage_collect (enum kind_of_key kk, int dek_no, uint8_t *key_addr)
{
  uint16_t hw;
  uintptr_t addr;
  int i, j, k;
  uint16_t dek_offset;
  uint8_t dek[3][DATA_ENCRYPTION_KEY_SIZE+2];
  uint8_t key_material[KEY_STORAGE_SIZE_MAX];
  int len;

  len = ((key_addr[0] &0x0f << 8) | key_addr[1]) + 2;
  memcpy (key_material, key_addr, len);
  if ((len & 1))
    key_material[len] = 0;

  for (i = j = 0; i < 3; i++)
    {
      /* Skip the DEK_NO entry, it's about to be updated.  */
      if (i == dek_no)
	continue;

      dek_offset = pkc_key[kk].dek_offset[i];
      if (dek_offset != 0)
	memcpy (dek[j++], key_addr+dek_offset, DATA_ENCRYPTION_KEY_SIZE+2);
    }

  flash_erase_page ((uintptr_t)key_addr);

  addr = (uintptr_t)key_addr;
  i = 0;
  for (i = 0; i < (len+1)/2; i++)
    {
      hw = key_material[i*2] | (key_material[i*2+1] << 8);
      if (flash_program_halfword (addr, hw) != 0)
	return -1;
      addr += 2;
    }

  for (k = 0; k < j; k++)
    {
      int dek_no_k;

      dek_no_k = ((dek[k][0]&0x70 >> 4));
      for (i = 0; i < (DATA_ENCRYPTION_KEY_SIZE+2)/2; i++)
	{
	  hw = dek[k][i*2] | (dek[k][i*2+1] << 8);
	  if (flash_program_halfword (addr, hw) != 0)
	    return -1;
	  addr += 2;
	}

      pkc_key[kk].dek_offset[dek_no_k] = addr - (uintptr_t)key_addr;
    }

  pkc_key[kk].last_dek_offset = addr - (uintptr_t)key_addr;
  return 0;
}

int
flash_key_dek_write (enum kind_of_key kk, int dek_no, const uint8_t *dek)
{
  uint16_t hw;
  uintptr_t addr;
  int i;
  uint8_t *key_addr = flash_key_getpage (kk);
  uint16_t dek_offset;

  dek_offset = pkc_key[kk].last_dek_offset;
  if (dek_offset + 2 + DATA_ENCRYPTION_KEY_SIZE >= flash_page_size)
    {
      flash_key_garbage_collect (kk, dek_no, key_addr);
      dek_offset = pkc_key[kk].last_dek_offset;
    }

  pkc_key[kk].dek_offset[dek_no] = dek_offset;
  pkc_key[kk].last_dek_offset = dek_offset + 2 + DATA_ENCRYPTION_KEY_SIZE;

  addr = (uintptr_t)key_addr + dek_offset;
  hw = FLASH_PKC_TAG_DEK | (dek_no << 4) | (DATA_ENCRYPTION_KEY_SIZE << 8);
  if (flash_program_halfword (addr, hw) != 0)
    return -1;
  addr += 2;

  for (i = 0; i < DATA_ENCRYPTION_KEY_SIZE/2; i++)
    {
      hw = dek[i*2] | (dek[i*2+1]<<8);
      if (flash_program_halfword (addr, hw) != 0)
	return -1;
      addr += 2;
    }

  return 0;
}

void
flash_clear_halfword (uintptr_t addr)
{
  flash_program_halfword (addr, 0);
}


void
flash_put_data_internal (const uint8_t *p, uint16_t hw)
{
  flash_program_halfword ((uintptr_t)p, hw);
}

void
flash_put_data (uint16_t hw)
{
  uint8_t *p;

  p = flash_data_pool_allocate (2);
  if (p == NULL)
    {
      DEBUG_INFO ("data allocation failure.\r\n");
    }

  flash_program_halfword ((uintptr_t)p, hw);
}


void
flash_bool_clear (const uint8_t **addr_p)
{
  const uint8_t *p;

  if ((p = *addr_p) == NULL)
    return;

  flash_program_halfword ((uintptr_t)p, 0);
  *addr_p = NULL;
}

void
flash_bool_write_internal (const uint8_t *p, int nr)
{
  flash_program_halfword ((uintptr_t)p, nr);
}

const uint8_t *
flash_bool_write (uint8_t nr)
{
  uint8_t *p;
  uint16_t hw = nr;

  p = flash_data_pool_allocate (2);
  if (p == NULL)
    {
      DEBUG_INFO ("bool allocation failure.\r\n");
      return NULL;
    }

  flash_program_halfword ((uintptr_t)p, hw);
  return p;
}


void
flash_enum_clear (const uint8_t **addr_p)
{
  flash_bool_clear (addr_p);
}

void
flash_enum_write_internal (const uint8_t *p, int nr, uint8_t v)
{
  uint16_t hw = nr | (v << 8);

  flash_program_halfword ((uintptr_t)p, hw);
}

const uint8_t *
flash_enum_write (uint8_t nr, uint8_t v)
{
  uint8_t *p;
  uint16_t hw = nr | (v << 8);

  p = flash_data_pool_allocate (2);
  if (p == NULL)
    {
      DEBUG_INFO ("enum allocation failure.\r\n");
      return NULL;
    }

  flash_program_halfword ((uintptr_t)p, hw);
  return p;
}


int
flash_cnt123_get_value (const uint8_t *p)
{
  if (p == NULL)
    return 0;
  else
    {
      uint8_t v = *p;

      /*
       * After erase, a halfword in flash memory becomes 0xffff.
       * The halfword can be programmed to any value.
       * Then, the halfword can be programmed to zero.
       *
       * Thus, we can represent value 1, 2, and 3.
       */
      if (v == 0xff)
	return 1;
      else if (v == 0x00)
	return 3;
      else
	return 2;
    }
}

void
flash_cnt123_write_internal (const uint8_t *p, int which, int v)
{
  uint16_t hw;

  hw = NR_COUNTER_123 | (which << 8);
  flash_program_halfword ((uintptr_t)p, hw);

  if (v == 1)
    return;
  else if (v == 2)
    flash_program_halfword ((uintptr_t)p+2, 0xc3c3);
  else				/* v == 3 */
    flash_program_halfword ((uintptr_t)p+2, 0);
}

void
flash_cnt123_increment (uint8_t which, const uint8_t **addr_p)
{
  const uint8_t *p;
  uint16_t hw;

  if ((p = *addr_p) == NULL)
    {
      p = flash_data_pool_allocate (4);
      if (p == NULL)
	{
	  DEBUG_INFO ("cnt123 allocation failure.\r\n");
	  return;
	}
      hw = NR_COUNTER_123 | (which << 8);
      flash_program_halfword ((uintptr_t)p, hw);
      *addr_p = p + 2;
    }
  else
    {
      uint8_t v = *p;

      if (v == 0)
	return;

      if (v == 0xff)
	hw = 0xc3c3;
      else
	hw = 0;

      flash_program_halfword ((uintptr_t)p, hw);
    }
}

void
flash_cnt123_clear (const uint8_t **addr_p)
{
  const uint8_t *p;

  if ((p = *addr_p) == NULL)
    return;

  flash_program_halfword ((uintptr_t)p, 0);
  p -= 2;
  flash_program_halfword ((uintptr_t)p, 0);
  *addr_p = NULL;
}


#if defined(CERTDO_SUPPORT)
int
flash_erase_binary (uint8_t file_id)
{
  if (file_id == FILEID_CH_CERTIFICATE)
    {
      const uint8_t *p = &ch_certificate_start;
      if (flash_check_blank (p, FLASH_CH_CERTIFICATE_SIZE) == 0)
	{
	  flash_erase_page ((uintptr_t)p);
	  if (FLASH_CH_CERTIFICATE_SIZE > flash_page_size)
	    flash_erase_page ((uintptr_t)p + flash_page_size);
	}

      return 0;
    }

  return -1;
}
#endif


int
flash_write_binary (uint8_t file_id, const uint8_t *data,
		    uint16_t len, uint16_t offset)
{
  uint16_t maxsize;
  const uint8_t *p;

  if (file_id == FILEID_SERIAL_NO)
    {
      maxsize = 6;
      p = &openpgpcard_aid[8];
    }
#if defined(CERTDO_SUPPORT)
  else if (file_id == FILEID_CH_CERTIFICATE)
    {
      maxsize = FLASH_CH_CERTIFICATE_SIZE;
      p = &ch_certificate_start;
    }
#endif
  else
    return -1;

  if (offset + len > maxsize || (offset&1) || (len&1))
    return -1;
  else
    {
      uint16_t hw;
      uintptr_t addr;
      int i;

      if (flash_check_blank (p + offset, len)  == 0)
	return -1;

      addr = (uintptr_t)p + offset;
      for (i = 0; i < len/2; i++)
	{
	  hw = data[i*2] | (data[i*2+1]<<8);
	  if (flash_program_halfword (addr, hw) != 0)
	    flash_warning ("DO WRITE ERROR");
	  addr += 2;
	}

      return 0;
    }
}
