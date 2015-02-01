/*
 * This program implements the stream cipher MICKEY 2.0 faster version
 * Author - Steve Babbage (Vodafone Group R&D) and Matthew Dodd (Independet consultant).
 * The MICKEY 2.0 home page - http://www.ecrypt.eu.org/stream/.
 * ------------------------
 * Developed: Rostislav Gashin (rost1993). The State University of Syktyvkar (Amplab).
 * Assistant project manager: Lipin Boris (dzruyk).
 * Project manager: Grisha Sitkarev.
 * ------------------------
 * Russia, Komi Republic, Syktyvkar - 1.02.2015, version 1.
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "mickey.h"

// MICKEY 2.0 key length in bytes
#define MICKEY		10

// Feedback mask associated with the register R
uint32_t R_MASK[4] = { 0x1279327B, 0xB5546660,
		       0xDF87818F, 0x00000003 };

// Input mask associated with register S
uint32_t COMP0[4] = { 0x6AA97A30, 0x7942A809, 
		      0x057EBFEA, 0x00000006 };

// Second input mask associated with register S
uint32_t COMP1[4] = { 0xDD629E9A, 0xE3A21D63, 
		      0x91C23DD7, 0x00000001 };

// Feedback mask associated with the register S for clock control_bit = 0
uint32_t S_MASK0[4] = { 0x9FFA7FAF, 0xAF4A9381,
			0x9CEC5802, 0x00000001 };

// Feedback mask associated with the register S for clock control_bit = 1
uint32_t S_MASK1[4] = { 0x4C8CB877, 0x4911B063,
			0x40FBC52B, 0x00000008 };
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
	uint32_t r[4];
	uint32_t s[4];
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
CLOCK_R(struct mickey_context *ctx, const uint8_t input_bit_r, const uint8_t control_bit_r)
{
	int feedback_bit, carry0, carry1, carry2;

	feedback_bit = ((ctx->r[3] >> 3) & 1) ^ input_bit_r;
	carry0 = (ctx->r[0] >> 31) & 1;
	carry1 = (ctx->r[1] >> 31) & 1;
	carry2 = (ctx->r[2] >> 31) & 1;

	if(control_bit_r) {
		ctx->r[0] ^= (ctx->r[0] << 1);
		ctx->r[1] ^= (ctx->r[1] << 1) ^ carry0;
		ctx->r[2] ^= (ctx->r[2] << 1) ^ carry1;
		ctx->r[3] ^= (ctx->r[3] << 1) ^ carry2;
	}
	else {
		ctx->r[0] = (ctx->r[0] << 1);
		ctx->r[1] = (ctx->r[1] << 1) ^ carry0;
		ctx->r[2] = (ctx->r[2] << 1) ^ carry1;
		ctx->r[3] = (ctx->r[3] << 1) ^ carry2;
	}

	if(feedback_bit) {
		ctx->r[0] ^= R_MASK[0];
		ctx->r[1] ^= R_MASK[1];
		ctx->r[2] ^= R_MASK[2];
		ctx->r[3] ^= R_MASK[3];
	}
}

// Function clocking the register S
static void
CLOCK_S(struct mickey_context *ctx, const uint8_t input_bit_s, const uint8_t control_bit_s)
{
	int feedback_bit, carry0, carry1, carry2;

	feedback_bit = ((ctx->s[3] >> 3) & 1) ^ input_bit_s;
	carry0 = (ctx->s[0] >> 31) & 1;
	carry1 = (ctx->s[1] >> 31) & 1;
	carry2 = (ctx->s[2] >> 31) & 1;

	ctx->s[0] = (ctx->s[0] << 1) ^ ((ctx->s[0] ^ COMP0[0]) & ((ctx->s[0] >> 1) ^ (ctx->s[1] << 31) ^ COMP1[0]) & 0xFFFFFFFE);
	ctx->s[1] = (ctx->s[1] << 1) ^ ((ctx->s[1] ^ COMP0[1]) & ((ctx->s[1] >> 1) ^ (ctx->s[2] << 31) ^ COMP1[1])) ^ carry0;
	ctx->s[2] = (ctx->s[2] << 1) ^ ((ctx->s[2] ^ COMP0[2]) & ((ctx->s[2] >> 1) ^ (ctx->s[3] << 31) ^ COMP1[2])) ^ carry1;
	ctx->s[3] = (ctx->s[3] << 1) ^ ((ctx->s[3] ^ COMP0[3]) & ((ctx->s[3] >> 1) ^ COMP1[3]) & 0x7) ^ carry2;

	if(feedback_bit) {
		if(control_bit_s) {
			ctx->s[0] ^= S_MASK1[0];
			ctx->s[1] ^= S_MASK1[1];
			ctx->s[2] ^= S_MASK1[2];
			ctx->s[3] ^= S_MASK1[3];
		}
		else {
			ctx->s[0] ^= S_MASK0[0];
			ctx->s[1] ^= S_MASK0[1];
			ctx->s[2] ^= S_MASK0[2];
			ctx->s[3] ^= S_MASK0[3];
		}
	}
}

// Function clocking the overall generator
static void
CLOCK_KG(struct mickey_context *ctx, const uint8_t mixing, const uint8_t input_bit)
{
	int control_bit_r, control_bit_s;

	control_bit_r = ((ctx->s[1] >> 2) ^ (ctx->r[2] >> 3)) & 1;
	control_bit_s = ((ctx->r[1] >> 1) ^ (ctx->s[2] >> 3)) & 1;

	if(mixing)
		CLOCK_R(ctx, ((ctx->s[1] >> 18) & 1) ^ input_bit, control_bit_r);
	else
		CLOCK_R(ctx, input_bit, control_bit_r);
	
	CLOCK_S(ctx, input_bit, control_bit_s);
}

// Function key loading and initialization (filling registers R and S)
static void
mickey_key_setup(struct mickey_context *ctx)
{
	uint8_t input_bit;
	int i;

	memset(ctx->r, 0, sizeof(ctx->r));
	memset(ctx->s, 0, sizeof(ctx->s));
	
	for(i = 0; i < 80; i++) {
		input_bit = (ctx->iv[i/8] >> (7 - (i & 0x7))) & 1;
		CLOCK_KG(ctx, 1, input_bit);
	}
	
	for(i = 0; i < 80; i++) {
		input_bit = (ctx->key[i/8] >> (7 - (i & 0x7))) & 1;
		CLOCK_KG(ctx, 1, input_bit);
	}
	
	for(i = 0; i < 100; i++)
		CLOCK_KG(ctx, 1, 0);
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
 * out - pointer on output 
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
			CLOCK_KG(ctx, 0, 0);
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

