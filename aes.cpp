#include <cstring>
#include <arpa/inet.h>
#include <openssl/aes.h>
#include <stdlib.h>
#include "aes.h"
#include "pkcs7.h"
#include "rand.h"
#include "xors.h"

void genRandomAESKey(unsigned char* bytes, unsigned int length)
{
	if (length != 16 && length != 24 && length != 32)
		throw AESException("Invalid key size");
	seedRand();
	for (unsigned int i = 0; i < length; i++)
		bytes[i] = rand() % 256;
}

void aesEncryptECB(const unsigned char* source, unsigned char* dest, const unsigned char* key, const unsigned int sourceLen, const unsigned int keyLen)
{
	AES_KEY k;
	AES_set_encrypt_key(key, keyLen * 8, &k);

	for (unsigned int i = 0; i < sourceLen / AES_BLOCK_SIZE; i++)
	{
		aesEncryptBlock(source + (i * AES_BLOCK_SIZE), dest + (i * AES_BLOCK_SIZE), &k);
	}
}

void aesDecryptECB(const unsigned char* source, unsigned char* dest, const unsigned char* key, const unsigned int sourceLen, const unsigned int keyLen)
{
	AES_KEY k;
	AES_set_decrypt_key(key, keyLen * 8, &k);

	for (unsigned int i = 0; i < sourceLen / AES_BLOCK_SIZE; i++)
	{
		aesDecryptBlock(source + (i * AES_BLOCK_SIZE), dest + (i * AES_BLOCK_SIZE), &k);
	}
}

void aesEncryptCBC(const unsigned char* source, unsigned char* dest, const unsigned char* key, const unsigned char* iv, const unsigned int sourceLen, const unsigned int keyLen)
{
	AES_KEY k;
	AES_set_encrypt_key(key, keyLen * 8, &k);
	unsigned char* foo = new unsigned char[AES_BLOCK_SIZE];
	unsigned char* bar = new unsigned char[AES_BLOCK_SIZE];
	unsigned char* tmp = NULL;
	memcpy(foo, iv, AES_BLOCK_SIZE);

	for (unsigned int i = 0; i < sourceLen / AES_BLOCK_SIZE; i++)
	{
		xorBuffer(source + (i * AES_BLOCK_SIZE), foo, &tmp, AES_BLOCK_SIZE);
		aesEncryptBlock(tmp, foo, &k);
		memcpy(dest + (i * AES_BLOCK_SIZE), foo, AES_BLOCK_SIZE);
		delete [] tmp;
	}

	delete [] foo;
	delete [] bar;
}

void aesDecryptCBC(const unsigned char* source, unsigned char* dest, const unsigned char* key, const unsigned char* iv, const unsigned int sourceLen, const unsigned int keyLen)
{
	AES_KEY k;
	AES_set_decrypt_key(key, keyLen * 8, &k);
	unsigned char* foo = new unsigned char[AES_BLOCK_SIZE];
	unsigned char* bar = new unsigned char[AES_BLOCK_SIZE];
	unsigned char* tmp = NULL;
	memcpy(foo, iv, AES_BLOCK_SIZE);

	for (unsigned int i = 0; i < sourceLen / AES_BLOCK_SIZE; i++)
	{
		aesDecryptBlock(source + (i * AES_BLOCK_SIZE), bar, &k);
		xorBuffer(foo, bar, &tmp, AES_BLOCK_SIZE);
		memcpy(dest + (i * AES_BLOCK_SIZE), tmp, AES_BLOCK_SIZE);
		delete [] tmp;
		memcpy(foo, source + (i * AES_BLOCK_SIZE), AES_BLOCK_SIZE);
	}

	delete [] foo;
	delete [] bar;
}

void aesEncryptCTR(const unsigned char* source, unsigned char* dest, const unsigned char* key, const unsigned char* nonce, const unsigned int sourceLen, const unsigned int keyLen)
{
	AES_KEY k;
	AES_set_encrypt_key(key, keyLen * 8, &k);
	unsigned char* keystream = new unsigned char[AES_BLOCK_SIZE];
	unsigned char* input = new unsigned char[AES_BLOCK_SIZE];
	unsigned char* output = new unsigned char[AES_BLOCK_SIZE];

	for (uint64_t i = 0; i <= sourceLen / AES_BLOCK_SIZE; i++)
	{
		memcpy(input, nonce, 8);
		if (htonl(47) == 47) // big endian
			(input[8]) = __builtin_bswap64(i);
		memcpy(&input[8], &i, sizeof(i));
		aesEncryptBlock(input, output, &k);
		for (unsigned int j = 0; j < AES_BLOCK_SIZE && i * AES_BLOCK_SIZE + j < sourceLen; j++)
			dest[i * AES_BLOCK_SIZE + j] = source[i * AES_BLOCK_SIZE + j] ^ output[j];
	}

	delete [] output;
	delete [] input;
	delete [] keystream;	
}

void aesDecryptCTR(const unsigned char* source, unsigned char* dest, const unsigned char* key, const unsigned char* nonce, const unsigned int sourceLen, const unsigned int keyLen)
{
	// decrypt is the same as encrypt chump.
	aesEncryptCTR(source, dest, key, nonce, sourceLen, keyLen);
}

void aesEncryptBlock(const unsigned char* source, unsigned char* dest, const AES_KEY* k)
{
	AES_encrypt(source, dest, k);
}

void aesDecryptBlock(const unsigned char* source, unsigned char* dest, const AES_KEY* k)
{
	AES_decrypt(source, dest, k);
}

void challenge11(const unsigned char* source, unsigned char** dest, const unsigned int sourceLen, unsigned int* destLen)
{
	seedRand();
	unsigned char* key = new unsigned char[AES_BLOCK_SIZE];
	unsigned char* appended = NULL;
	unsigned char* padded = NULL;
	unsigned int prefixLen = rand() % 5 + 5;
	unsigned int suffixLen = rand() % 5 + 5;
	unsigned char* prefix = new unsigned char[prefixLen];
	unsigned char* suffix = new unsigned char[suffixLen];
	
	for (unsigned int i = 0; i < prefixLen; i++) prefix[i] = rand() % 256;
	for (unsigned int i = 0; i < suffixLen; i++) suffix[i] = rand() % 256;

	*destLen = (((prefixLen + suffixLen + sourceLen) / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
	appended = new unsigned char[*destLen];
	
	memcpy(appended, prefix, prefixLen);
	memcpy(appended + prefixLen, source, sourceLen);
	memcpy(appended + sourceLen + prefixLen, suffix, suffixLen);

	addPKCS7Pad(appended, &padded, sourceLen + prefixLen + suffixLen, *destLen);
	genRandomAESKey(key, AES_BLOCK_SIZE);

	*dest = new unsigned char[*destLen];

	if (rand() % 2)
	{
		aesEncryptECB(padded, *dest, key, *destLen, AES_BLOCK_SIZE);
	} else {
		unsigned char* iv = new unsigned char[16];
		genRandomAESKey(iv, 16);
		aesEncryptCBC(padded, *dest, key, iv, *destLen, AES_BLOCK_SIZE);
		delete [] iv;
	}

	delete [] key;
	delete [] padded;
	delete [] suffix;
	delete [] prefix;
	delete [] appended;
}
