/* 
 * ---------------------------------------------------------------------------
 * OpenAES License
 * ---------------------------------------------------------------------------
 * Copyright (c) 2012, Nabil S. Al Ramli, www.nalramli.com
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   - Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 * ---------------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "oaes_lib.h"

OAES_CTX *ctx = NULL;


int file_crypto_init(void) {
  ctx = oaes_alloc();
  if (NULL == ctx) {
    printf("Error: Failed to initialize OAES.\n");
    return 1;
  }
  return 0;
}

int file_crypto_close(OAES_CTX *ctx) {
  if (OAES_RET_SUCCESS != oaes_free(&ctx)) {
    printf("Error: Failed to uninitialize OAES.\n");
    return 1;
  }
  return 0;
}

int file_crypto_key_gen(OAES_CTX *ctx) {
  int i;
  size_t key_size = 32; // AES256
  uint8_t *data = (uint8_t *) calloc(key_size, sizeof(uint8_t));

  for (i = 0; i < key_size; i++ )
    data[i] = (uint8_t) 1; // rand();

  if (OAES_RET_SUCCESS != oaes_key_import_data(ctx, data, key_size)) {
    printf("Error: Failed to generate OAES 256 bit key.\n");
    return 1;
  }
  return 0;
}

int file_crypto_encrypt(OAES_CTX *ctx,
                        uint8_t *msg, size_t msg_len,
                        uint8_t **enbuf, size_t *enbuf_len) {
  uint8_t _pad = 1;
  uint8_t _iv[OAES_BLOCK_SIZE] = "";

  // estimate buffer size for encryption
  if (OAES_RET_SUCCESS != oaes_encrypt(ctx, (const uint8_t*) msg, msg_len,
                                       NULL, enbuf_len, NULL, NULL)) {
    printf("Error: Failed to retrieve required buffer size for encryption.\n");
    return 1;
  }

  // allocate buffer for encryption
  *enbuf = (uint8_t *) calloc(*enbuf_len, sizeof(uint8_t));
  if (NULL == *enbuf) {
    printf("Error: Failed to allocate memory.\n");
    return 1;
  }

  // add salt
  memcpy(_iv, "1234567890123456", OAES_BLOCK_SIZE);

  // encrypt msg
  if (OAES_RET_SUCCESS != oaes_encrypt(ctx, (const uint8_t*) msg, msg_len,
                                       *enbuf, enbuf_len, _iv, &_pad)) {
    printf("Error: Encryption failed.\n");
    return 1;
  }

  return 0;
}

int file_crypto_decrypt(OAES_CTX *ctx,
                        uint8_t *enbuf, size_t enbuf_len,
                        uint8_t **debuf, size_t *debuf_len) {
  uint8_t _pad = 1;
  uint8_t _iv[OAES_BLOCK_SIZE] = "";

  // estimate buffer size for decryption
  if (OAES_RET_SUCCESS != oaes_decrypt(ctx, enbuf, enbuf_len,
                                       NULL, debuf_len, NULL, NULL)) {
    printf("Error: Failed to retrieve required buffer size for decryption.\n");
    return 1;
  }

  // allocate buffer for decryption
  *debuf = (uint8_t *) calloc(*debuf_len, sizeof(uint8_t));
  if (NULL == *debuf) {
    printf( "Error: Failed to allocate memory.\n" );
    return 1;
  }

  // add salt
  memcpy(_iv, "1234567890123456", OAES_BLOCK_SIZE);

  // decrypt msg
  if (OAES_RET_SUCCESS != oaes_decrypt(ctx, enbuf, enbuf_len,
                                       *debuf, debuf_len, _iv, _pad)) {
    printf("Error: Decryption failed.\n");
    return 1;
  }

  return 0;
}

int file_crypto_encrypt_case(OAES_CTX *ctx, const char *src, const char *dst) {

  // open input file
  FILE *ifp = fopen(src, "rb");
  if (NULL == ifp) {
    printf("Error: Failed to open the input file.\n");
    return 1;
  }

  // open output file
  FILE *ofp = fopen(dst, "wb+");
  if (NULL == ifp) {
    fclose(ifp);
    printf("Error: Failed to open the output file.\n");
    return 1;
  }

  // load input file into buffer
  fseek(ifp, 0L, SEEK_END);
  size_t msg_len = ftell(ifp);
  fseek(ifp, 0L, SEEK_SET);
  uint8_t *msg = (uint8_t *) calloc(msg_len, sizeof(uint8_t));
  fread(msg, msg_len*sizeof(uint8_t), 1, ifp);

  // encrypt sequence
  uint8_t *enbuf; size_t enbuf_len;
  file_crypto_encrypt(ctx, msg, msg_len, &enbuf, &enbuf_len);

  // export to output file
  fwrite(enbuf, 1, enbuf_len, ofp);

  // release resource
  free(msg);
  free(enbuf);
  fclose(ofp);
  fclose(ifp);

  // return success
  return 0;
}

uint8_t *file_crypto_decrypt_case(OAES_CTX *ctx, const char *src, const char *dst) {

  // open input file
  FILE *ifp = fopen(src, "rb");
  if (NULL == ifp) {
    printf("Error: Failed to open the input file.\n");
    return NULL;
  }

  // open output file
  FILE *ofp = fopen(dst, "wb+");
  if (NULL == ifp) {
    fclose(ifp);
    printf("Error: Failed to open the output file.\n");
    return NULL;
  }

  // load input file into buffer
  fseek(ifp, 0L, SEEK_END);
  size_t msg_len = ftell(ifp);
  fseek(ifp, 0L, SEEK_SET);
  uint8_t *msg = (uint8_t *) calloc(msg_len, sizeof(uint8_t));
  fread(msg, msg_len*sizeof(uint8_t), 1, ifp);

  // decrypt sequence
  uint8_t *debuf; size_t debuf_len;
  file_crypto_decrypt(ctx, msg, msg_len, &debuf, &debuf_len);

  // export to output file
  fwrite(debuf, 1, debuf_len, ofp);

  // release resource
  free(msg);
  free(debuf);
  fclose(ofp);
  fclose(ifp);

  return NULL;
}

int main(void) {

  file_crypto_init();
  file_crypto_key_gen(ctx);
  file_crypto_encrypt_case(ctx, "script.lua",  "script.elua");
  file_crypto_decrypt_case(ctx, "script.elua", "script.dlua");
  file_crypto_close(ctx);

  return 0;
}
