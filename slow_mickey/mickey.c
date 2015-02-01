/*
 * This program implements the stream cipher MICKEY 2.0 slow version.
 * Author - Steve Babbage (Vodafone Group R&D) and Matthew Dodd (Independet consultant).
 * The MICKEY 2.0 home page - http://www.ecrypt.eu.org/stream/.
 * ------------------------
 * Developed: Rostislav Gashin (rost1993). The State University of Syktyvkar (Amplab).
 * Assistant project manager: Lipin Boris (dzruyk).
 * Project manager: Grisha Sitkarev.
 * ------------------------
 * Russia, Komi Republic, Syktyvkar - 19.01.2015, version 1.
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "mickey.h"

// MICKEY 2.0 key length in bytes
#define MICKEY		10

// Array RTAPS for the register R
uint8_t RTAPS[100] = { 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1,
		       1, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1,
		       0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1,
		       0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0,
		       1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1,
		       1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0,
		       0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1,
		       1, 1, 0, 1, 1, 1, 1, 0, 0 };

// Array COMP0, COMP1, FB0, FB1 for the register S
uint8_t COMP0[99] = { 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1,
		      0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
		      1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0,
		      1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1,
		      1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 
		      1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0,
		      1, 0, 0, 0, 0, 0, 0, 1, 1 };

uint8_t COMP1[99] = { 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0,
		      1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0,
		      1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1,
		      0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0,
		      0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1,
		      1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0,
		      0, 0, 1, 0, 0, 1, 1, 0, 0 };

uint8_t FB0[100] = { 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1,
		     0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0,
		     0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1,
		     0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1,
		     0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		     1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0,
		     1, 1, 1, 0, 0, 1, 1, 0, 0, 0 };

uint8_t FB1[100] = { 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0,
		     1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0,
		     1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1,
		     1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1,
		     0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1,
		     0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0,
		     0, 0, 0, 0, 1, 0, 0, 0, 0, 1 };

/*
 * MICKEY 2.0 context
 * keylen - chiper key length in bytes
 * key - chiper key
 * iv - initialization vector
 * r - register r
 * s - register s
*/
struct mickey_context {
	int keylen;
	uint8_t key[10];
	uint8_t iv[10];
	uint8_t r[100];
	uint8_t s[100];
};

// Allocates memory for the mickey_context
struct mickey_context *
mickey_context_new(void)
{
	struct mickey_context *ctx;
	ctx = malloc(sizeof(*ctx));

	if(ctx == NULL)
		return NULL;
	
	memset(ctx, 0, sizeof(*ctx));

	return ctx;
}

// Delete mickey_context
void
mickey_context_free(struct mickey_context **ctx)
{
	free(*ctx);
	*ctx = NULL;
}

// Function clocking the register R
static void
CLOCK_R(uint8_t r[100], const uint8_t input_bit_r, const uint8_t control_bit_r) 
{
	uint8_t feedback_bit;
	int i;

	feedback_bit = r[99] ^ input_bit_r;

	if(control_bit_r) {

		if(feedback_bit) {
			for(i = 99; i > 0; i--)
				r[i] = r[i-1] ^ r[i] ^ RTAPS[i];
			r[0] = r[0] ^ RTAPS[0];
		}
		else {
			for(i = 99; i > 0; i--)
				r[i] = r[i-1] ^ r[i];
		}
	}
	else {

		if(feedback_bit) {
			for(i = 99; i > 0; i--)
				r[i] = r[i-1] ^ RTAPS[i];
			r[0] = RTAPS[0];
		}
		else {
			for(i = 99; i > 0; i--)
				r[i] = r[i-1];
			r[0] = 0;
		}
	}					
}

// Function clocking the register S
static void
CLOCK_S(uint8_t s[100], const uint8_t input_bit_s, const uint8_t control_bit_s)
{
	uint8_t feedback_bit, s_temp[100];
	int i;

	feedback_bit = s[99] ^ input_bit_s;

	for(i = 98; i > 0; i--)
		s_temp[i] = s[i-1] ^ ((s[i] ^ COMP0[i]) & (s[i+1] ^ COMP1[i]));
	s_temp[0] = 0;
	s_temp[99] = s[98];

	if(feedback_bit) {

		if(control_bit_s) {
			for(i = 0; i < 100; i++)
				s[i] = s_temp[i] ^ FB1[i];
		}
		else {
			for(i = 0; i < 100; i++)
				s[i] = s_temp[i] ^ FB0[i];
		}
	}
	else {
		memcpy(s, s_temp, 100);
	}
}

// Function clocking the overall generator
static void
CLOCK_KG(uint8_t r[100], uint8_t s[100], const uint8_t mixing, const uint8_t input_bit)
{
	uint8_t control_bit_r, control_bit_s;
	
	control_bit_r = s[34] ^ r[67];
	control_bit_s = s[67] ^ r[33];

	if(mixing)
		CLOCK_R(r, input_bit ^ s[50], control_bit_r);
	else
		CLOCK_R(r, input_bit, control_bit_r);
	
	CLOCK_S(s, input_bit, control_bit_s);
}

// Function key loading and initialization (filling registers R and S)
static void
mickey_key_setup(struct mickey_context *ctx)
{
	uint8_t input_bit;
	int i;
	
	memset(ctx->r, 0, 100);
	memset(ctx->s, 0, 100);

	for(i = 0; i < 80; i++) {
		input_bit = (ctx->iv[i/8] >> (7 - (i & 0x7))) & 1;
		CLOCK_KG(ctx->r, ctx->s, 1, input_bit);
	}
	
	for(i = 0; i < 80; i++) {
		input_bit = (ctx->key[i/8] >> (7 - (i & 0x7))) & 1;
		CLOCK_KG(ctx->r, ctx->s, 1, input_bit);
	}

	for(i = 0; i < 100; i++)
		CLOCK_KG(ctx->r, ctx->s, 1, 0);
}

// Fill the mickey_context (key and iv)
// Return value: 0 (if all is well), -1 (is all bad)
int
mickey_set_key_and_iv(struct mickey_context *ctx, const uint8_t *key, const int keylen, const uint8_t iv[10])
{
	if(keylen <= MICKEY)
		ctx->keylen = keylen;
	else
		return -1;
	
	memcpy(ctx->key, key, keylen);
	memcpy(ctx->iv, iv, 10);

	mickey_key_setup(ctx);

	return 0;
}

/*
 * MICKEY 2.0 encrypt function
 * ctx - pointer on mickey_context
 * buf - pointer on buffer data
 * buflen - length the data buffer
 * out - pointer on output array
*/
void
mickey_encrypt(struct mickey_context *ctx, const uint8_t *buf, const uint32_t buflen, uint8_t *out)
{
	uint32_t i, j;
	int keystream;

	for(i = 0; i < buflen; i++) {
		
		out[i] = buf[i];

		for(j = 0; j < 8; j++) {
			keystream = ((ctx->r[0] ^ ctx->s[0]) & 1) << (7-j);
			CLOCK_KG(ctx->r, ctx->s, 0, 0);
			out[i] ^= keystream;
		}
	}
}

// MICKEY 2.0 decrypt function. See mickey_encrypt
void
mickey_decrypt(struct mickey_context *ctx, const uint8_t *buf, const uint32_t buflen, uint8_t *out)
{
	mickey_encrypt(ctx, buf, buflen, out);
}

