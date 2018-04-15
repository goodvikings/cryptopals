#include <cstring>
#include "aes.h"
#include "ctr_bit_flip.h"
#include "misc.h"
#include "pkcs7.h"

#include <iostream>
using namespace std;

const static unsigned char key[] = {0x83, 0x07, 0xae, 0x1a, 0xc9, 0x05, 0xcc, 0xf9, 0x4c, 0x8c, 0xb5, 0x98, 0xe7, 0x17, 0x1f, 0x84};
const static unsigned char nonce[] = {0x7a, 0x6a, 0x3f, 0x32, 0x63, 0x72, 0x37, 0x71};

void c26_encrypt(const unsigned char* source, unsigned char** dest, const unsigned int sourceLen, unsigned int* destLen)
{
	const unsigned char prefix[] = "comment1=cooking%20MCs;userdata=";
	const unsigned char suffix[] = ";comment2=%20like%20a%20pound%20of%20bacon";
	unsigned char* encoded = NULL;
	unsigned int encodedLen = 0;
	unsigned char* appended = NULL;

	encode(source, sourceLen, &encoded, &encodedLen);

	*destLen = strlen((char*)prefix) + strlen((char*)suffix) + encodedLen;
	appended = new unsigned char[*destLen];

	memcpy(appended, prefix, strlen((char*)prefix));
	memcpy(appended + strlen((char*)prefix), encoded, encodedLen);
	memcpy(appended + strlen((char*)prefix) + encodedLen, suffix, strlen((char*)suffix));

	*dest = new unsigned char[*destLen];

	aesEncryptCTR(appended, *dest, key, nonce, *destLen, 16);
	
	delete [] appended;
	delete [] encoded;
}

bool c26_checkForAdmin(const unsigned char* source, const unsigned int sourceLen)
{
	unsigned char* plain = new unsigned char[sourceLen];
	bool retVal = false;
	const unsigned char needle[] = ";admin=true;";

	aesDecryptCTR(source, plain, key, nonce, sourceLen, 16);
	
	retVal = searchForText(plain, sourceLen, needle, strlen((char*)needle));
	
	delete [] plain;

	return retVal;
}
