#include <string>
#include <cstring>
#include "aes.h"
#include "cbc_padding.h"
#include "encoders.h"
#include "pkcs7.h"
#include "rand.h"
using namespace std;

const static unsigned char key[] = {0x00, 0xd6, 0xb2, 0xf9, 0x9c, 0xab, 0xd5, 0xa0, 0x93, 0x4e, 0x53, 0xfd, 0x3c, 0x2b, 0x86, 0x8d};
const static string strings[10] = {"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=", "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=", "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==", "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==", "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl", "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==", "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==", "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=", "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=", "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"};

void c17_attack_block(const unsigned char* iv, const unsigned char* block, unsigned char* dest, const unsigned int blocksize);
void c17_build_chosen(unsigned char* block, const unsigned char* known, const unsigned int blocksize, const unsigned int step);

void c17_encrypt(unsigned char** dest, unsigned char** iv, unsigned int* destLen, unsigned int* ivLen)
{
	seedRand();
	unsigned int foo = rand() % 10;
	unsigned char* stringRaw = NULL;
	unsigned int stringRawLen = 0;
	unsigned char* padded = NULL;

	from_base64((unsigned char*) strings[foo].c_str(), &stringRaw, strings[foo].length(), &stringRawLen);

	*destLen = ((stringRawLen / 16) + 1) * 16;

	addPKCS7Pad(stringRaw, &padded, stringRawLen, *destLen);

	*ivLen = 16;
	*iv = new unsigned char[*ivLen];
	genRandomAESKey(*iv, *ivLen);

	*dest = new unsigned char[*destLen];
	aesEncryptCBC(padded, *dest, key, *iv, *destLen, 16);

	delete [] padded;
	delete [] stringRaw;
}

bool c17_decryptAndCheckPadding(const unsigned char* source, const unsigned int sourceLen, const unsigned char* iv, const unsigned int ivLen)
{
	unsigned char* plain = new unsigned char[sourceLen];
	unsigned char* unpadded = NULL;
	unsigned int unpaddedLen = 0;
	bool retVal = true;

	aesDecryptCBC(source, plain, key, iv, sourceLen, 16);
	
	try
	{
		removePCKSPad(plain, &unpadded, sourceLen, &unpaddedLen, 16);
	}
	catch (PKCS7Exception e)
	{
		retVal = false;
	}
	
	delete [] plain;
	delete [] unpadded;

	return retVal;
}

void c17_attack(const unsigned char* source, const unsigned int sourceLen, unsigned char** dest, unsigned int* destLen, const unsigned char* iv, const unsigned int blocksize)
{
	*dest = new unsigned char[sourceLen];
	*destLen = sourceLen;

	memset(*dest, 0, *destLen);

	c17_attack_block(iv, source, *dest, 16);
	for (unsigned int i = 0; i < (sourceLen / blocksize) - 1; i++)
	{
		c17_attack_block(source + (i * blocksize), source + ((i + 1) * blocksize), *dest + ((i + 1) * blocksize), 16);
	}
}

void c17_attack_block(const unsigned char* iv, const unsigned char* block, unsigned char* dest, const unsigned int blocksize)
{
	unsigned char* localIV = NULL;

	for (unsigned int j = 0; j < blocksize; j++)
	{
		for (int i = 255; i >= 0; i--)
		{
			localIV = new unsigned char[blocksize];
			memcpy(localIV, iv, blocksize);
			c17_build_chosen(localIV, dest, blocksize, j + 1);
			localIV[blocksize - j - 1] ^= i;
			
			if (c17_decryptAndCheckPadding(block, blocksize, localIV, blocksize))
			{
				dest[blocksize - j - 1] = (char)((j + 1) ^ i);
				delete [] localIV;
				break;
			}

			delete [] localIV;
		}
	}
}

void c17_build_chosen(unsigned char* block, const unsigned char* known, const unsigned int blocksize, const unsigned int step)
{
	for (unsigned int i = blocksize - step + 1; i < blocksize; i++)
	{
		block[i] ^= known[i] ^ step;
	}
}
