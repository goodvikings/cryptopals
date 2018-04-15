#include <string.h>

#include "mt19937.h"
#include "mt19937_cipher.h"
#include "rand.h"
#include "aes.h"
#include "misc.h"

void genRandString(const unsigned int min, const unsigned int max, unsigned char** dest, unsigned int* destLen);

void mtEncrypt(const unsigned char* source, const unsigned int sourceLen, unsigned char* dest, unsigned int key)
{
	mt19937 mt(key);
	
	for (unsigned int i = 0; i < sourceLen; i++)
		dest[i] = source[i] ^ (char)mt.getRand32();
}

void mtDecrypt(const unsigned char* source, const unsigned int sourceLen, unsigned char* dest, unsigned int key)
{
	// decrypt is the same as encrypt boyo
	mtEncrypt(source, sourceLen, dest, key);
}

void c24(const unsigned char* source, const unsigned int sourceLen, unsigned char** dest, unsigned int* destLen)
{
	seedRand();
	unsigned char* prefix = NULL;
	unsigned int prefixLen = 0;
	unsigned char* full = NULL;
	unsigned int key = (unsigned short)rand();
	
	genRandString(10, 50, &prefix, &prefixLen);
	
	*destLen = prefixLen + sourceLen;
	full = new unsigned char[*destLen];
	*dest = new unsigned char[*destLen];
	
	memcpy(full, prefix, prefixLen);
	memcpy(full + prefixLen, source, sourceLen);
	
	mtEncrypt(full, *destLen, *dest, key);
	
	delete [] full;
	delete [] prefix;
}

unsigned int attack_c24(const unsigned char* ct, const unsigned int ctLen, const unsigned char* searchText, const int searchtextLen)
{
	unsigned char* buff = new unsigned char[ctLen];
	unsigned int retVal = 0;
	
	for (unsigned long i = 0; i < 65536; i++)
	{
		mtDecrypt(ct, ctLen, buff, i);
				
		if (searchForText(buff, ctLen, searchText, searchtextLen))
		{
			retVal = i;
			break;
		}
	}
	
	delete [] buff;
	
	return retVal;
}

void genRandString(const unsigned int min, const unsigned int max, unsigned char** dest, unsigned int* destLen)
{
	seedRand();

	*destLen = (rand() % (max - min)) + min;
	*dest = new unsigned char[*destLen];
	for (unsigned int i = 0; i < *destLen; i++)
		(*dest)[i] = (char)rand();
}
