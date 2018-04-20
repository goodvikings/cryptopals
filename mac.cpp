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
