#include <stdint.h>
#include "shake256.h"

int
eddsa_sign_448 (uint8_t *out, const uint8_t *input, unsigned int ilen, 
		const uint8_t *a_in, const uint8_t *seed, const uint8_t *pk);
void
eddsa_public_key_448 (uint8_t *pk, const uint8_t *a_in);


static const uint8_t raw_sk[57] =  {
  0x6c, 0x82, 0xa5, 0x62, 0xcb, 0x80, 0x8d, 0x10,
  0xd6, 0x32, 0xbe, 0x89, 0xc8, 0x51, 0x3e, 0xbf,
  0x6c, 0x92, 0x9f, 0x34, 0xdd, 0xfa, 0x8c, 0x9f,
  0x63, 0xc9, 0x96, 0x0e, 0xf6, 0xe3, 0x48, 0xa3,
  0x52, 0x8c, 0x8a, 0x3f, 0xcc, 0x2f, 0x04, 0x4e,
  0x39, 0xa3, 0xfc, 0x5b, 0x94, 0x49, 0x2f, 0x8f,
  0x03, 0x2e, 0x75, 0x49, 0xa2, 0x00, 0x98, 0xf9,
  0x5b
};

#include <stdio.h>

static void
printout_hex (uint8_t *p, int len)
{
  int i;

  for (i = 0; i < len; i++)
    printf ("%02x", p[i]);
  puts ("");
}


int
main (int argc, const char *argv[])
{
  shake_context ctx;
  uint8_t hash[2*57];
  uint8_t *sk;
  uint8_t *seed;
  uint8_t pk[57];
  uint8_t sig[57*2];

  shake256_start (&ctx);
  shake256_update (&ctx, raw_sk, 57);
  shake256_finish (&ctx, (uint8_t *)hash, 2*57);

  sk = hash;
  seed = hash + 57;

  printout_hex (sk, 56);

  eddsa_public_key_448 (pk, sk);
  printout_hex (pk, 57);

  eddsa_sign_448 (sig, "", 0, sk, seed, pk);
  printout_hex (sig, 57*2);
}
