#include <cstring>
#include "pkcs7.h"

void addPKCS7Pad(const unsigned char* source, unsigned char** dest, const unsigned int sourceLen, const unsigned int destLen)
{
	if (destLen < sourceLen) throw PKCS7Exception("Dest needs to be larger than source");
	if (destLen - sourceLen > 255) throw PKCS7Exception("Difference too large");

	*dest = new unsigned char[destLen];
	memcpy(*dest, source, sourceLen);

	for (unsigned int i = sourceLen; i < destLen; i++)
	{
		(*dest)[i] = destLen - sourceLen;
	}
}

void removePCKSPad(const unsigned char* source, unsigned char** dest, const unsigned int sourceLen, unsigned int* destLen, const unsigned int blocksize)
{
	const unsigned int padVal = source[sourceLen - 1];

	if (padVal > blocksize || padVal == 0)
		throw PKCS7Exception("Invalid padding");

	for (unsigned int i = 0; i < padVal; i++)
	{
		if (source[sourceLen - 1 - i] != padVal)
			throw PKCS7Exception("Invalid padding");
	}

	*destLen = sourceLen - padVal;
	*dest = new unsigned char[*destLen];
	memcpy(*dest, source, *destLen);
}
