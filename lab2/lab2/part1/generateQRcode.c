#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>

#include "lib/encoding.h"

#define SecretHexLength 20
#define SecretHexBitLength 80

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

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",issuer, accountName, secret_hex);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator
	const char * IssuerEncoded = urlEncode(issuer);
	const char * accountNameEncoded = urlEncode(accountName);
	
	//convert the input hex into int
	char IntSecret_hex[SecretHexLength];
	for (int i = 0; i < SecretHexLength; i++) {
		if(isdigit(secret_hex[i])){//0-9
			IntSecret_hex[i] = secret_hex[i] - '0';
		}else{//A-F
			IntSecret_hex[i] = secret_hex[i] - 'A' + 10;
		}
    }

	//convert to uint8_t
	uint8_t uint8_Secret_hex[SecretHexLength/2];//each hex = 4 bit
	for (int i = 0; i < SecretHexLength; i+=2) { // Iterate through each byte (2 hex)
        uint8_Secret_hex[i/2] = IntSecret_hex[i] * 16 + IntSecret_hex[i+1];
    }

	//encode secret into base32
	uint8_t *SecretHexEncoded = (uint8_t*) malloc(sizeof(uint8_t)*(SecretHexBitLength/5)); //5 bits a group
	base32_encode(uint8_Secret_hex, SecretHexLength/2, SecretHexEncoded, SecretHexBitLength/5);

	//form uri
	int uriLength = strlen(IssuerEncoded) + strlen(accountNameEncoded) + SecretHexBitLength/5 
					+ strlen("otpauth://totp/?issuer=&secret=&period=30"); 
	char uri[uriLength];
	snprintf(uri, uriLength, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", accountNameEncoded, IssuerEncoded, SecretHexEncoded);

	displayQRcode(uri);

	return (0);
}
