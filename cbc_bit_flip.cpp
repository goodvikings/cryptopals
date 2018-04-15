#include <cstring>
#include <string>
#include "aes.h"
#include "cbc_bit_flip.h"
#include "misc.h"
#include "pkcs7.h"
using namespace std;

const static unsigned char key[] = {0x83, 0x07, 0xae, 0x1a, 0xc9, 0x05, 0xcc, 0xf9, 0x4c, 0x8c, 0xb5, 0x98, 0xe7, 0x17, 0x1f, 0x84};
const static unsigned char iv[] = {0x83, 0x07, 0xae, 0x1a, 0xc9, 0x05, 0xcc, 0xf9, 0x4c, 0x8c, 0xb5, 0x98, 0xe7, 0x17, 0x1f, 0x84};

void c16_encrypt(const unsigned char* source, unsigned char** dest, const unsigned int sourceLen, unsigned int* destLen)
{
	const unsigned char prefix[] = "comment1=cooking%20MCs;userdata=";
	const unsigned char suffix[] = ";comment2=%20like%20a%20pound%20of%20bacon";
	unsigned char* encoded = NULL;
	unsigned int encodedLen = 0;
	unsigned char* appended = NULL;
	unsigned int appendedLen = 0;
	unsigned char* padded = NULL;

	encode(source, sourceLen, &encoded, &encodedLen);

	appendedLen = strlen((char*)prefix) + strlen((char*)suffix) + encodedLen;
	appended = new unsigned char[appendedLen];

	memcpy(appended, prefix, strlen((char*)prefix));
	memcpy(appended + strlen((char*)prefix), encoded, encodedLen);
	memcpy(appended + strlen((char*)prefix) + encodedLen, suffix, strlen((char*)suffix));

	*destLen = ((appendedLen / 16) + 1) * 16;

	addPKCS7Pad(appended, &padded, appendedLen, *destLen);

	*dest = new unsigned char[*destLen];

	aesEncryptCBC(padded, *dest, key, iv, *destLen, 16);

	delete [] padded;
	delete [] appended;
	delete [] encoded;
}

bool c16_checkForAdmin(const unsigned char* source, const unsigned int sourceLen)
{
	unsigned char* plain = new unsigned char[sourceLen];
	bool retVal = false;
	const unsigned char needle[] = ";admin=true;";

	aesDecryptCBC(source, plain, key, iv, sourceLen, 16);

	for (unsigned int i = 0; i < sourceLen - strlen((char*)needle); i++)
	{
		if (!strncmp((char*)plain + i, (char*)needle, strlen((char*)needle)))
		{
			retVal = true;
			break;
		}
	}

	delete [] plain;

	return retVal;
}

bool c27_decrypt(const unsigned char* source, const unsigned int sourceLen, unsigned char* dest)
{
	aesDecryptCBC(source, dest, key, iv, sourceLen, 16);
	
	for (unsigned int i = 0; i < sourceLen; i++)
		if (dest[i] >= 128)
			return false;
	return true;
}
