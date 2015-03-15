/*
 * This library implements the stream cipher MICKEY 2.0 faster version
 * Author - Steve Babbage (Vodafone Group R&D) and Matthew Dodd (Independet consultant)
 * Mickey 2.0 - the winner eSTREAM Project. Home page - http://www.ecrypt.eu.org/stream/
*/

#ifndef MICKEY_H_
#define MICKEY_H_

struct mickey_context;

struct mickey_context *mickey_context_new(void);
void mickey_context_free(struct mickey_context **ctx);

int mickey_set_key_and_iv(struct mickey_context *ctx, const uint8_t *key, const int keylen, const uint8_t iv[10], const int ivlen);

void mickey_encrypt(struct mickey_context *ctx, const uint8_t *buf, const uint32_t buflen, uint8_t *out);
void mickey_decrypt(struct mickey_context *ctx, const uint8_t *buf, const uint32_t buflen, uint8_t *out);

void mickey_test_vectors(struct mickey_context *ctx);

#endif
