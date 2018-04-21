#include <cstring>
#include "mac.h"
#include "md4.h"
#include "sha1.h"

static const unsigned char key[] = {0x49, 0x5e, 0x4d, 0xbb, 0x17, 0x65, 0xda, 0x4c, 0xd7, 0x85, 0x4c, 0x90, 0xd8, 0x45, 0xaf, 0xed};
static const unsigned int keyLen = 16;

void generateSHA1Mac(const unsigned char* message, const unsigned int messageLen, unsigned char** result, unsigned int* resultLen)
{
	SHA1 digestor;

	digestor.update(key, keyLen);
	digestor.update(message, messageLen);

	digestor.digest(result, resultLen);
}

bool verifySHA1Mac(const unsigned char* message, const unsigned int messageLen, const unsigned char* hash, const unsigned int hashLen)
{
	unsigned char* result;
	unsigned int resultLen;
	bool retVal;

	generateSHA1Mac(message, messageLen, &result, &resultLen);

	retVal = !memcmp(result, hash, hashLen);

	delete [] result;

	return retVal;
}

void generateMD4Mac(const unsigned char* message, const unsigned int messageLen, unsigned char** result, unsigned int* resultLen)
{
	md4 digestor;

	digestor.update(key, keyLen);
	digestor.update(message, messageLen);

	digestor.digest(result, resultLen);
}

bool verifyMD4Mac(const unsigned char* message, const unsigned int messageLen, const unsigned char* hash, const unsigned int hashLen)
{
	unsigned char* result;
	unsigned int resultLen;
	bool retVal;

	generateMD4Mac(message, messageLen, &result, &resultLen);

	retVal = !memcmp(result, hash, hashLen);

	delete [] result;

	return retVal;
}

void generateSHA1HMac(const unsigned char* message, const unsigned int messageLen, unsigned char** result, unsigned int* resultLen)
{
	const unsigned int blocksize = 64;
	unsigned char* keyPrime = new unsigned char[blocksize];
	unsigned char* iPad = new unsigned char[blocksize];
	unsigned char* oPad = new unsigned char[blocksize];
	unsigned char* iHash = NULL;
	SHA1* digestor;

	memset(keyPrime, 0, blocksize);
	memset(iPad, 0x36, blocksize);
	memset(oPad, 0x5c, blocksize);

	if (keyLen > blocksize)
	{
		digestor = new SHA1;
		unsigned char* hash = NULL;
		unsigned int hashLen = 0;
		digestor->update(key, keyLen);
		digestor->digest(&hash, &hashLen);

		delete [] hash;
		delete digestor;
	} else {
		memcpy(keyPrime, key, keyLen);
	}

	for (unsigned int i = 0; i < blocksize; i++)
	{
		iPad[i] ^= keyPrime[i];
		oPad[i] ^= keyPrime[i];
	}

	digestor = new SHA1;
	digestor->update(iPad, blocksize);
	digestor->update(message, messageLen);
	digestor->digest(&iHash, resultLen);
	delete digestor;

	digestor = new SHA1;
	digestor->update(oPad, blocksize);
	digestor->update(iHash, *resultLen);
	digestor->digest(result, resultLen);
	delete digestor;

	delete [] iPad;
	delete [] oPad;
	delete [] iHash;
	delete [] keyPrime;
}

bool verifySHA1HMac(const unsigned char* message, const unsigned int messageLen, const unsigned char* hash, const unsigned int hashLen)
{
	unsigned char* result;
	unsigned int resultLen;
	bool retVal;

	generateSHA1HMac(message, messageLen, &result, &resultLen);

	retVal = !memcmp(result, hash, hashLen);

	delete [] result;

	return retVal;
}
