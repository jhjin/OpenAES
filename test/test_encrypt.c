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

/*
 * 
 */
int main(int argc, char** argv) {

	OAES_CTX * ctx = NULL;
	unsigned char *_encbuf, *_decbuf;
	size_t _encbuf_len, _decbuf_len, _buf_len;
	char *_buf;
	
	if( argc != 2 )
	{
		printf(
				"Usage:\n"
				"\t%s <text>\n",
				argv[0]
		);
		return EXIT_FAILURE;
	}

	oaes_sprintf( NULL, &_buf_len,
			(const unsigned char *)argv[1], strlen( argv[1] ) );
	_buf = (char *) calloc( _buf_len, sizeof( char ) );
	printf( "\n***** plaintext  *****\n" );
	if( _buf )
	{
		oaes_sprintf( _buf, &_buf_len,
				(const unsigned char *)argv[1], strlen( argv[1] ) );
		printf( _buf );
	}
	printf( "\n**********************\n" );
	free( _buf );
	
	ctx = oaes_init();
	oaes_key_gen_128(ctx);
	oaes_encrypt( ctx, (const unsigned char *)argv[1], strlen( argv[1] ),
			NULL, &_encbuf_len );
	_encbuf = (unsigned char *) calloc( _encbuf_len, sizeof( char ) );
	
	if( NULL == _encbuf )
		return EXIT_FAILURE;

	oaes_encrypt( ctx, (const unsigned char *)argv[1], strlen( argv[1] ),
			_encbuf, &_encbuf_len );
	oaes_decrypt( ctx, _encbuf, _encbuf_len, NULL, &_decbuf_len );
	_decbuf = (unsigned char *) calloc( _decbuf_len, sizeof( char ) );
	
	if( NULL == _decbuf )
	{
		free( _encbuf );
		return EXIT_FAILURE;
	}
	
	oaes_decrypt( ctx, _encbuf, _encbuf_len, _decbuf, &_decbuf_len );

	oaes_uninit( &ctx );
	
	oaes_sprintf( NULL, &_buf_len, _encbuf, _encbuf_len );
	_buf = (char *) calloc( _buf_len, sizeof( char ) );
	printf( "\n***** cyphertext *****\n" );
	if( _buf )
	{
		oaes_sprintf( _buf, &_buf_len, _encbuf, _encbuf_len );
		printf( _buf );
	}
	printf( "\n**********************\n" );
	free( _buf );
	
	oaes_sprintf( NULL, &_buf_len, _decbuf, _decbuf_len );
	_buf = (char *) calloc( _buf_len, sizeof( char ) );
	printf( "\n***** plaintext  *****\n" );
	if( _buf )
	{
		oaes_sprintf( _buf, &_buf_len, _decbuf, _decbuf_len );
		printf( _buf );
	}
	printf( "\n**********************\n\n" );
	free( _buf );
	
	free( _encbuf );
	free( _decbuf );

	return (EXIT_SUCCESS);
}
