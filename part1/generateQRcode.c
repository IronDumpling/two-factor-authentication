#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

#define SECRET_LEN 20
#define URI_LEN    256

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

int
main(int argc, char * argv[])
{
	if ( argc != 4 ) {
		printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
		return(-1);
	}

	char *	issuer = argv[1];
	char *	accountName = argv[2];
	char *	secret_hex = argv[3];

	assert (strlen(secret_hex) <= 20);

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator

	char URI[URI_LEN];
	// Obtain encoded_account
	const char * encoded_account = urlEncode(accountName);
	// Obtain encoded_issuer
	const char * encoded_issuer = urlEncode(issuer);
	// Obtain encoded_secret
	uint8_t secret_bin[SECRET_LEN / 2];
	hex_to_bin(secret_hex, secret_bin);
	char encoded_secret[SECRET_LEN];
	base32_encode(secret_bin, 10, (uint8_t *) encoded_secret, 128);

	// Cast the string with encoded_account / encoded_issuer / encoded_secret to form the URI
	snprintf(URI, URI_LEN, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", encoded_account, encoded_issuer, encoded_secret);

	displayQRcode(URI);

	return (0);
}
