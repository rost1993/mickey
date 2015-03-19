/*
 * This library implements the stream cipher MICKEY 2.0 faster version
 * Author - Steve Babbage (Vodafone Group R&D) and Matthew Dodd (Independet consultant)
 * Mickey 2.0 - the winner eSTREAM Project. Home page - http://www.ecrypt.eu.org/stream/
*/

#ifndef MICKEY_H
#define MICKEY_H

/*
 * MICKEY 2.0 context
 * keylen - chiper key length in bytes
 * ivlen - vector initialization in bytes
 * key - chiper key 
 * iv - initialization vector
 * r - register r
 * s - register s
*/
struct mickey_context {
	int keylen;
	int ivlen;
	uint8_t key[10];
	uint8_t iv[10];
	uint32_t r[4];
	uint32_t s[4];
};

void mickey_init(struct mickey_context *ctx);

int mickey_set_key_and_iv(struct mickey_context *ctx, const uint8_t *key, const int keylen, const uint8_t iv[10], const int ivlen);

void mickey_encrypt(struct mickey_context *ctx, const uint8_t *buf, const uint32_t buflen, uint8_t *out);
void mickey_decrypt(struct mickey_context *ctx, const uint8_t *buf, const uint32_t buflen, uint8_t *out);

void mickey_test_vectors(struct mickey_context *ctx);

#endif
