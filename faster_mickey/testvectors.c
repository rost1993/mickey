#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "mickey.h"

int
main(void)
{
	uint8_t key1[10] = { 0x12, 0x34, 0x56, 0x78, 0x9A,
			     0xBC, 0xDE, 0xF0, 0x12, 0x34 };
	
	uint8_t key2[10] = { 0xF1, 0x1A, 0x56, 0x27, 0xCE,
			     0x43, 0xB6, 0x1F, 0x89, 0x12 };
	
	uint8_t iv1[10] = { 0x12, 0x34, 0x56, 0x78, 0x9A,
			    0xBC, 0xDE, 0xF0, 0x12, 0x34 };

	uint8_t iv2[10] = {0x9C, 0x53, 0x2F, 0x8A, 0xC3,
			   0xEA, 0x4B, 0x2E, 0xA0, 0xF5 };
	
	struct mickey_context ctx;

	mickey_init(&ctx);

	if(mickey_set_key_and_iv(&ctx, key1, 10, iv1, 10)) {
		printf("Filling error mickey context!\n");
		exit(1);
	}
	
	mickey_test_vectors(&ctx);

	mickey_init(&ctx);

	if(mickey_set_key_and_iv(&ctx, key2, 10, iv2, 10)) {
		printf("Filling error mickey context!\n");
		exit(1);
	}

	mickey_test_vectors(&ctx);

	return 0;
}

