#include <cstring>
#include <string>
#include "aes.h"
#include "ecb.h"
#include "encoders.h"
#include "language.h"
#include "pkcs7.h"
using namespace std;

unsigned int getBlockOffset(const unsigned int blocksize, void (*oracle)(const unsigned char*, unsigned char**, const unsigned int, unsigned int*));
void getFlagBlock(const unsigned int blocksize, unsigned char* flagBlock, void (*oracle)(const unsigned char*, unsigned char**, const unsigned int, unsigned int*));
bool contains(const unsigned char* haystack, const unsigned char* needle, const unsigned int haystackLen, const unsigned int needleLen);
unsigned int getPrependLen(const unsigned int blocksize, void (*oracle)(const unsigned char*, unsigned char**, const unsigned int, unsigned int*));
void buildPrepend(const unsigned int knownLen, const unsigned int blocksize, const unsigned int extra, unsigned char** dest, unsigned int* destLen);

void c12_encryptOracle(const unsigned char* source, unsigned char** dest, const unsigned int sourceLen, unsigned int* destLen)
{
	// In real world challenges, everything here is secret
	const unsigned char key[] = {0x83, 0x07, 0xae, 0x1a, 0xc9, 0x05, 0xcc, 0xf9, 0x4c, 0x8c, 0xb5, 0x98, 0xe7, 0x17, 0x1f, 0x84};
	//const unsigned char secretb64[] = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
	const unsigned char secretb64[] = "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw==";
	unsigned char* secretRaw = NULL;
	unsigned int secretRawLen = 0;

	from_base64(secretb64, &secretRaw, strlen((char*)secretb64), &secretRawLen);

	unsigned char* appended = NULL;
	unsigned char* padded = NULL;
	
	*destLen = (((secretRawLen + sourceLen) / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;

	appended = new unsigned char[*destLen];

	memcpy(appended, source, sourceLen);
	memcpy(appended + sourceLen, secretRaw, secretRawLen);

	addPKCS7Pad(appended, &padded, sourceLen + secretRawLen, *destLen);

	*dest = new unsigned char[*destLen];

	aesEncryptECB(padded, *dest, key, *destLen, AES_BLOCK_SIZE);

	delete [] padded;
	delete [] appended;
	delete [] secretRaw;
}

void c14_encryptOracle(const unsigned char* source, unsigned char** dest, const unsigned int sourceLen, unsigned int* destLen)
{
	// In real world challenges, everything here is secret
	const unsigned char key[] = {0x83, 0x07, 0xae, 0x1a, 0xc9, 0x05, 0xcc, 0xf9, 0x4c, 0x8c, 0xb5, 0x98, 0xe7, 0x17, 0x1f, 0x84};
	const unsigned char junkb64[] = "vlZv9+dCmFK7yYQ+V434CzzMMyVy+MWNY3USTDHZiVR3Cg==";
	const unsigned char secretb64[] = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
	//const unsigned char secretb64[] = "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw==";
	unsigned char* secretRaw = NULL;
	unsigned int secretRawLen = 0;
	unsigned char* junkRaw = NULL;
	unsigned int junkRawLen = 0;
	unsigned char* appended = NULL;
	unsigned char* padded = NULL;
	
	from_base64(junkb64, &junkRaw, strlen((char*)junkb64), &junkRawLen);
	from_base64(secretb64, &secretRaw, strlen((char*)secretb64), &secretRawLen);

	*destLen = (((junkRawLen + secretRawLen + sourceLen) / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
	appended = new unsigned char[*destLen];

	memcpy(appended, junkRaw, junkRawLen);
	memcpy(appended + junkRawLen, source, sourceLen);
	memcpy(appended + junkRawLen + sourceLen, secretRaw, secretRawLen);
	addPKCS7Pad(appended, &padded, sourceLen + secretRawLen + junkRawLen, *destLen);

	*dest = new unsigned char[*destLen];

	aesEncryptECB(padded, *dest, key, *destLen, AES_BLOCK_SIZE);

	delete [] padded;
	delete [] appended;
	delete [] secretRaw;
	delete [] junkRaw;
}

void getUnknownString(const unsigned int blocksize, unsigned char** out, unsigned int* outLen, void (*oracle)(const unsigned char*, unsigned char**, const unsigned int, unsigned int*))
{
	unsigned char* prependText = NULL;
	unsigned int prependTextLen = 0;
	unsigned char* needle_encrypted = NULL;
	unsigned int destLen = 0;
	string known = "";

	unsigned int blockOffest = getBlockOffset(blocksize, oracle);
	unsigned int prependLen = getPrependLen(blocksize, oracle);

	while (1)
	{
		bool found = false;
		buildPrepend(known.length(), blocksize, prependLen, &prependText, &prependTextLen);
		oracle(prependText, &needle_encrypted, prependTextLen, &destLen);
		for (unsigned int i = 0; i < 256; i++)
		{
			string test = string((char*)prependText, prependTextLen);
			unsigned char* test_encrypted = NULL;
			test += known;
			test += char(i);
			oracle((unsigned char*)test.c_str(), &test_encrypted, test.length(), &destLen);
			if (!memcmp((char*)needle_encrypted + (blockOffest * blocksize), (char*)test_encrypted + (blockOffest * blocksize), ((known.length() / blocksize) + 1) * blocksize))
			{
				delete [] test_encrypted;
				known += (char) i;
				found = true;
				break;
			}
			delete [] test_encrypted;
		}
		delete [] needle_encrypted;
		delete [] prependText;
		if (!found) break;
	}
	if (!known.length())
	{
		return;
	}
	*outLen = known.length() - 1;
	*out = new unsigned char[*outLen];
	memcpy(*out, known.c_str(), *outLen);
}

unsigned int getBlockSize(void (*oracle)(const unsigned char*, unsigned char**, const unsigned int, unsigned int*))
{
	unsigned char* input = new unsigned char[128];
	unsigned char* dest = NULL;
	unsigned int destLen = 0;
	unsigned int retVal = 0;

	// only to supporess valgrind warning for unintialised values, we don't actually care if it's junk
	memset(input, 0, 128);

	// feed zero length input, get ciphertext len
	oracle(input, &dest, 0, &destLen);
	delete [] dest;

	for (unsigned int i = 1; i < 128; i++)
	{
		oracle(input, &dest, i, &retVal);
		delete [] dest;
		if (retVal - destLen)
			break;
	}

	delete [] input;
	return retVal - destLen;
}

bool isECBMode(const unsigned int blocksize, void (*oracle)(const unsigned char*, unsigned char**, const unsigned int, unsigned int*))
{
	unsigned char* input = new unsigned char[3 * blocksize];
	unsigned char* dest = NULL;
	unsigned int destLen = 0;
	bool retVal = false;

	memset(input, 'A', 3 * blocksize);
	oracle(input, &dest, 3 * blocksize, &destLen);
	retVal = countZeroHammings(dest, destLen, blocksize) > 0 ? 1 : 0;
	
	delete [] dest;
	delete [] input;

	return retVal;
}

unsigned int getBlockOffset(const unsigned int blocksize, void (*oracle)(const unsigned char*, unsigned char**, const unsigned int, unsigned int*))
{
	unsigned char* input = new unsigned char[3 * blocksize];
	unsigned char* ct = NULL;
	unsigned int ctLen = 0;
	unsigned int retVal = 0;

	memset(input, 'A', 3 * blocksize);
	oracle(input, &ct, 3 * blocksize, &ctLen);

	for (unsigned int i = 0; i < (ctLen / blocksize) - 1; i++)
	{
		if (!memcmp(ct + (i * blocksize), ct + ((i + 1) * blocksize), blocksize))
		{
			retVal = i;
			break;
		}
	}

	delete [] input;
	delete [] ct;

	return retVal;
}

void getFlagBlock(const unsigned int blocksize, unsigned char* flagBlock, void (*oracle)(const unsigned char*, unsigned char**, const unsigned int, unsigned int*))
{
	unsigned char* input = new unsigned char[3 * blocksize];
	unsigned char* ct = NULL;
	unsigned int ctLen = 0;

	memset(input, 'A', 3 * blocksize);
	oracle(input, &ct, 3 * blocksize, &ctLen);

	for (unsigned int i = 0; i < (ctLen / blocksize) - 1; i++)
	{
		if (!memcmp(ct + (i * blocksize), ct + ((i + 1) * blocksize), blocksize))
		{
			memcpy(flagBlock, ct + (i * blocksize), blocksize);
			break;
		}
	}

	delete [] ct;
	delete [] input;
}

unsigned int getPrependLen(const unsigned int blocksize, void (*oracle)(const unsigned char*, unsigned char**, const unsigned int, unsigned int*))
{
	unsigned char* ct = NULL;
	unsigned int ctLen = 0;
	unsigned char* input = NULL;
	unsigned char* flag = new unsigned char[blocksize];
	unsigned int retVal = 0;

	getFlagBlock(blocksize, flag, oracle);

	for (unsigned int i = (blocksize * 2) - 1; i > 0 && !retVal; i--)
	{
		input = new unsigned char[i];
		memset(input, 'A', i);
		oracle(input, &ct, i, &ctLen);

		if (!contains(ct, flag, ctLen, blocksize))
		{
			retVal = i;
		}
		delete [] input;
		delete [] ct;
	}

	delete [] flag;

	return retVal - blocksize + 1;
}

bool contains(const unsigned char* haystack, const unsigned char* needle, const unsigned int haystackLen, const unsigned int needleLen)
{
	for (unsigned int i = 0; i < haystackLen - needleLen; i++)
	{
		if (!memcmp(needle, haystack + i, needleLen))
			return true;
	}
	return false;
}

void buildPrepend(const unsigned int knownLen, const unsigned int blocksize, const unsigned int extra, unsigned char** dest, unsigned int* destLen)
{
	*destLen = blocksize - knownLen % blocksize - 1 + extra;
	(*dest) = new unsigned char[*destLen];
	memset(*dest, 'A', *destLen);
}
