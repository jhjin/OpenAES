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

#ifndef _OAES_LIB_H
#define _OAES_LIB_H

#ifdef __cplusplus 
extern "C" {
#endif

#define OAES_VERSION "0.2.0"

typedef void OAES_CTX;

typedef enum
{
	OAES_RET_FIRST = 0,
	OAES_RET_SUCCESS = 0,
	OAES_RET_UNKNOWN,
	OAES_RET_ARG1,
	OAES_RET_ARG2,
	OAES_RET_ARG3,
	OAES_RET_ARG4,
	OAES_RET_ARG5,
	OAES_RET_NOKEY,
	OAES_RET_MEM,
	OAES_RET_BUF,
	OAES_RET_HEADER,
	OAES_RET_COUNT
} OAES_RET;

typedef enum
{
	OAES_OPTION_NONE = 0,
	OAES_OPTION_ECB = 1,
	OAES_OPTION_CBC = 2,
} OAES_OPTION;

typedef int OAES_OPTIONS;

/*
 * // usage:
 * 
 * OAES_CTX * ctx = oaes_init();
 * .
 * .
 * .
 * oaes_gen_key_xxx( ctx );
 * oaes_key_export( ctx, _buf, &_buf_len );
 * // or
 * oaes_key_import( ctx, _buf, _buf_len );
 * .
 * .
 * .
 * oaes_encrypt( ctx, m, m_len, c, &c_len );
 * .
 * .
 * .
 * oaes_decrypt( ctx, c, c_len, m, &m_len );
 * .
 * .
 * .
 * oaes_uninit( &ctx );
 */

OAES_CTX * oaes_init();

OAES_RET oaes_uninit( OAES_CTX ** ctx );

OAES_RET oaes_set_options( OAES_CTX * ctx, OAES_OPTIONS options );

OAES_RET oaes_key_gen_128( OAES_CTX * ctx );

OAES_RET oaes_key_gen_192( OAES_CTX * ctx );

OAES_RET oaes_key_gen_256( OAES_CTX * ctx );

// set data == NULL to get the required data_len
OAES_RET oaes_key_export( OAES_CTX * ctx,
		unsigned char * data, int * data_len );

OAES_RET oaes_key_import( OAES_CTX * ctx,
		const unsigned char * data, int data_len );

// set c == NULL to get the required c_len
OAES_RET oaes_encrypt( OAES_CTX * ctx,
		const unsigned char * m, size_t m_len, unsigned char * c, size_t * c_len );

// set m == NULL to get the required m_len
OAES_RET oaes_decrypt( OAES_CTX * ctx,
		const unsigned char * c, size_t c_len, unsigned char * m, size_t * m_len );

// set buf == NULL to get the required buf_len
OAES_RET oaes_sprintf(
		char * buf, size_t * buf_len, const unsigned char * data, size_t data_len );

#ifdef __cplusplus 
}
#endif

#endif // _OAES_LIB_H
