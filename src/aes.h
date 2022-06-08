#include <stdint.h>

#define AES_BLOCK_SIZE     16   /* in byte */

/*
 * For AES-256:
 *
 * Block size in bit = 128, Nb = 4 (= 128 / 32) (in 32-bit word)
 * Key size in bit = 256, Nk = 8 (= 256 / 32) (in 32-bit word)
 * Number of round Nr = 14
 *
 * Contextsize = Nb * (Nr + 1) = 60 (in 32-bit word)
 */
#define AES_KEY_SIZE       32   /* in byte */
#define AES_CONTEXT_SIZE   60   /* in word */

/**
 * AES context structure
 *
 */
typedef struct
{
  uint32_t rk[AES_CONTEXT_SIZE]; /*!<  AES round keys (60-words) */
} aes_context;

/**
 * AES key setup
 *
 * @param ctx      AES context
 * @param key      key
 *
 */
void aes_set_key (aes_context *ctx, const unsigned char key[AES_KEY_SIZE]);

/**
 * AES block encryption
 *
 * @param ctx      AES context
 * @param output   output block
 * @param input    input block
 *
 */
void aes_encrypt (const aes_context *ctx,
                  const unsigned char input[AES_BLOCK_SIZE],
                  unsigned char output[AES_BLOCK_SIZE]);

/**
 * AES key teardown
 *
 * @param ctx      AES context
 *
 */
void aes_clear_key (aes_context *ctx);


/**
 * AES counter mode encryption
 *
 * @param ctx      AES context
 * @param len      length of input/output
 * @param iv_off_p offset in the current stream_block
 * @param iv       iv and counter
 * @param st_block saved stream block
 * @param output   output
 * @param input    input
 *
 */
void aes_crypt_ctr (const aes_context *ctx, int len,
                    unsigned int *iv_off_p,
                    uint8_t iv[16], uint8_t str_block[16],
                    const uint8_t *input, uint8_t *output);
