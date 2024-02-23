#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <time.h>

#include "lib/sha1.h"

#define SECRET_LEN 20
#define CODE_LEN 6
#define DATA_SIZE  8

// Convert the char into decimal int, with numbers coded to be 0 to 9; 
// And letters coded to be right after numbers
int
char_to_dec(char c)
{
	if (c >= '0' && c <= '9') {
		// Case 1: the bit of secret is a number
		return c - '0';
	} else if (c >= 'A' && c <= 'F') {
		// Case 2: the bit of secret is an uppercase letter
		return c - 'A' + 10;
	} else if (c >= 'a' && c <= 'f') {
		// Case 3: the bit of secret is an lowercase letter
		return c - 'a' + 10;
	} else {
		// Invalid token
		return -1;
	}
}

// Convert a hex string into its binary equivalent
void
hex_to_bin(char * input, uint8_t * output)
{
	// As instructed, assume 20 is the only valid length
	if (strlen(input) != SECRET_LEN) {
		fprintf(stderr, "Error: Invalid length of secret.\n");
		exit(EXIT_FAILURE);
	}

	for (int i = 0; i < SECRET_LEN; i += 2) {
		// For each pair of hex's, shift the upper 4 bits of binary to the left by 4 bits
		// Append the lower 4 bits to the vacant positions
		output[i / 2] = (char_to_dec(input[i]) << 4) | char_to_dec(input[i + 1]);
	}
}

// Standard use of functions for SHA1 hashing
void
SHA1_hash(SHA1_INFO * ctx, uint8_t * buffer_1, int count_1, uint8_t * buffer_2, int count_2, uint8_t * digest) {
	sha1_init(ctx);
	sha1_update(ctx, buffer_1, count_1);
	sha1_update(ctx, buffer_2, count_2);
	sha1_final(ctx, digest);
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	// Convert the secret_hex into byte-wise version
	// Equivalently 8 binary bits allocated in one slot
	uint8_t secret_bin[SECRET_LEN / 2];
	hex_to_bin(secret_hex, secret_bin);

	// Instanciate inner padding
	uint8_t ipad[65];
	memset(ipad, 0, sizeof(ipad));
	memcpy(ipad, secret_bin, SECRET_LEN / 2);

	// Instanciate outer padding
	uint8_t opad[65];
	memset(opad, 0, sizeof(opad));
	memcpy(opad, secret_bin, SECRET_LEN / 2);

	// Initialize the correct values for both padding following this:
	// inner padding: 0x36 XOR'ed for 64 times
	// outer padding: 0x5c XOR'ed for 64 times
	for (int i = 0; i < 64; i++) {
		ipad[i] ^= 0x36;
		opad[i] ^= 0x5c;
	}

	uint8_t timer[DATA_SIZE];
	int counter = (time(NULL)) / 30;

	for (int i = 7; i >= 0; i--) {
		timer[i] = counter & 0xff;
		counter >>= 8;
	}

	SHA1_INFO ctx;
	uint8_t inner_hash[SHA1_DIGEST_LENGTH];
	uint8_t outer_hash[SHA1_DIGEST_LENGTH];

	// Compute inner SHA1 hash
	SHA1_hash(&ctx, ipad, 64, timer, DATA_SIZE, inner_hash);

	// Compute outer SHA1 hash
	SHA1_hash(&ctx, opad, 64, inner_hash, SHA1_DIGEST_LENGTH, outer_hash);

	// The part below was written with reference to RFC6238
	// Obtain binary code from the outer hashed value AKA HMAC
	int offset = outer_hash[SHA1_DIGEST_LENGTH - 1] & 0xf;
	int binary = ((outer_hash[offset] & 0x7f) << 24) |
					((outer_hash[offset + 1] & 0xff) << 16) |
					((outer_hash[offset + 2] & 0xff) << 8) |
					(outer_hash[offset + 3] & 0xff);

	// Instanciate a lookup table
	int powers_of_10[] = {1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000};

	// Evaluate and return True or False (1 or 0)
	return ((binary % powers_of_10[CODE_LEN]) == atoi(TOTP_string));
}

int
main(int argc, char * argv[])
{
	if ( argc != 3 ) {
		printf("Usage: %s [secretHex] [TOTP]\n", argv[0]);
		return(-1);
	}

	char *	secret_hex = argv[1];
	char *	TOTP_value = argv[2];

	assert (strlen(secret_hex) <= 20);
	assert (strlen(TOTP_value) == 6);

	printf("\nSecret (Hex): %s\nTOTP Value: %s (%s)\n\n",
		secret_hex,
		TOTP_value,
		validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");

	return(0);
}
