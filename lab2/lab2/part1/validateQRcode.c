#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <stdlib.h>
#include "lib/sha1.h"

//convert from hex to binary
void hex_to_bin(const char *hex, uint8_t *bin) {
    size_t len = strlen(hex);

    for (size_t i = 0; i < len; i += 2) {
        uint8_t value = 0;

        if (hex[i] >= '0' && hex[i] <= '9') {
            value = (hex[i] - '0') << 4;
        } else if (hex[i] >= 'A' && hex[i] <= 'F') {
            value = (hex[i] - 'A' + 10) << 4;
        } else if (hex[i] >= 'a' && hex[i] <= 'f') {
            value = (hex[i] - 'a' + 10) << 4;
        }

        if (hex[i + 1] >= '0' && hex[i + 1] <= '9') {
            value |= hex[i + 1] - '0';
        } else if (hex[i + 1] >= 'A' && hex[i + 1] <= 'F') {
            value |= hex[i + 1] - 'A' + 10;
        } else if (hex[i + 1] >= 'a' && hex[i + 1] <= 'f') {
            value |= hex[i + 1] - 'a' + 10;
        }

        bin[i / 2] = value;
    }
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
    uint8_t bin[10];
	//first change secret_hex from hex to binary
    hex_to_bin(secret_hex, bin);
    
	//put 64 bit of 0x36 to inner padding and 64 bit of 0x5c to outer padding
    uint8_t ipad[64];
	uint8_t opad[64];
	for (int i = 0; i < 64; i++) {
    	ipad[i] = 0x36;
	}    
	for (int i = 0; i < 64; i++) {
        opad[i] = 0x5c;
	}

    //xor between binary secret_hex and padding, since binary secret key is only 10 bit long, xor 10 bits
    for (int i = 0; i < sizeof(bin); i++) {
        ipad[i] ^= bin[i];
        opad[i] ^= bin[i];
    }
    
    SHA1_INFO ctx;
    uint8_t inner_sha[SHA1_DIGEST_LENGTH];
    uint8_t outer_sha[SHA1_DIGEST_LENGTH];

	//creating HMAC using key and timestep, ensure that current time change 30 seconds
    uint64_t time_step = time(NULL) / 30;
    //converting the time_step from uint64_t into a big-endian uint8_t 
    //sha1 takes big endian. need to make time compatible for further processing
    uint8_t be_time_step[8];
    for (int i = 0; i < 8; i++) {
        be_time_step[7 - i] = (uint8_t)(time_step >> (i * 8));
    }
    
    //HMAC = H[(K XOR opad) + H((K XOR ipad) + M)]
    sha1_init(&ctx);
    sha1_update(&ctx, ipad, sizeof(ipad));
    sha1_update(&ctx, be_time_step, sizeof(be_time_step));
    sha1_final(&ctx, inner_sha);
    
    sha1_init(&ctx);
    sha1_update(&ctx, opad, sizeof(opad));
    sha1_update(&ctx, inner_sha, sizeof(inner_sha));
    sha1_final(&ctx, outer_sha);

	//follow generateTOTP function in pdf to do Dynamic Truncation & convert to decimal & modulo operation
	int offset = outer_sha[SHA1_DIGEST_LENGTH - 1] & 0xf;
    int binary =
        ((outer_sha[offset] & 0x7f) << 24) |
        ((outer_sha[offset + 1]& 0xff) << 16) |
        ((outer_sha[offset + 2]& 0xff) << 8) |
        (outer_sha[offset + 3] & 0xff);
	
    //since totp is 6 digit integer
    int totp = binary % 1000000;

    //change from integer to char to compare with user input
	char calc_TOTP_string[7]; 
    snprintf(calc_TOTP_string, sizeof(calc_TOTP_string), "%06d", totp);
	if (strcmp(TOTP_string, calc_TOTP_string) == 0){
		return 1;
	}else{
		return 0;
	}
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
