#include <cstring>
#include "aes.h"
#include "ctr_randomaccess.h"
#include "encoders.h"
#include "misc.h"

static unsigned char* key;
static unsigned char* nonce;

void ctrRANDRWEncryptFromFile(const char* filename, unsigned char** dest, unsigned int* destLen)
{
	unsigned char* source = NULL;
	unsigned int sourceLen = 0;
	unsigned char* sourceRaw = NULL;
	
	readFromFile(filename, &source, &sourceLen);
	from_base64(source, &sourceRaw, sourceLen, destLen);
	
	*dest = new unsigned char[*destLen];
	key = new unsigned char[16];
	nonce = new unsigned char[16]; // nonce is actually only 16, but we can get 8 more bytes no worries. Only the first 8 will be used
	
	genRandomAESKey(key, 16);
	genRandomAESKey(nonce, 16);
	
	aesEncryptCTR(sourceRaw, *dest, key, nonce, *destLen, 16);
	
	delete [] source;
	delete [] sourceRaw;
}

void ctrRANDRWEdit(unsigned char* ct, const unsigned int ctLen, unsigned int offset, const unsigned char* newPlain, const unsigned int newPlainLen)
{
	unsigned char* buff = new unsigned char[ctLen];
	
	if (offset + newPlainLen > ctLen)
		throw AESException("Out of range for random access edit");
	
	aesDecryptCTR(ct, buff, key, nonce, ctLen, 16);
	memcpy(buff + offset, newPlain, newPlainLen);
	aesEncryptCTR(buff, ct, key, nonce, ctLen, 16);
	
	delete [] buff;
}

void ctrRANDRWAttack(const unsigned char* ct, const unsigned int ctLen, unsigned char** plain)
{
	unsigned char* ctCopy = new unsigned char[ctLen];
	unsigned char* zeroes = new unsigned char[ctLen];
	*plain = new unsigned char[ctLen];
	
	memset(zeroes, 0, ctLen);
	memcpy(ctCopy, ct, ctLen);
	
	ctrRANDRWEdit(ctCopy, ctLen, 0, zeroes, ctLen); // ctCopy now holds the keystream
	
	for (unsigned int i = 0; i < ctLen; i++)
		(*plain)[i] = ct[i] ^ ctCopy[i];
	
	delete [] ctCopy;
	delete [] zeroes;
}

void ctrRANDRWDestroy()
{
	delete [] key;
	delete [] nonce;
}
