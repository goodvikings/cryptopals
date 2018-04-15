#include <limits>
#include <cstring>
#include "language.h"
#include "xors.h"
using namespace std;

void xorBuffer(const unsigned char* foo, const unsigned char* bar, unsigned char** dest, const unsigned int len)
{
	*dest = new unsigned char[len];
	for (unsigned int i = 0; i < len; i++)
	{
		(*dest)[i] = foo[i] ^ bar[i];
	}
}

void fillBufferRepeating(const unsigned char* source, const unsigned int sourceLen, unsigned char* dest, const unsigned int destLen)
{
	for (unsigned int i = 0; i < destLen; i++)
	{
		dest[i] = source[i % sourceLen];
	}
}

unsigned int findRepeatingXORKeyLength(const unsigned char* source, const unsigned int len, const unsigned char max)
{
	unsigned int keyLength = 0;
	float bestScore  = numeric_limits<float>::max();
	for (unsigned int keyLengthTest = 2; keyLengthTest < max; keyLengthTest++)
	{
		unsigned int count = 0;
		float current = 0;

		while ((count + 2) * keyLengthTest < len)
		{
			current += hammingDiffernece(source + (count * keyLengthTest), source + ((count + 1) * keyLengthTest), keyLengthTest) * 1.0 / keyLengthTest;
			count++;
		}
		current /= count;

		if (current < bestScore)
		{
			bestScore = current;
			keyLength = keyLengthTest;
		}
	}

	return keyLength;
}

unsigned char findRepeatingXORKey(const unsigned char* ciphertext, const unsigned int len)
{
	double best = 500;
	unsigned char foo = 0;

	for (unsigned int key = 0; key < 256; key++)
	{
		unsigned char* keybuff = new unsigned char[len];
		unsigned char* plaintext = NULL;
		memset(keybuff, (unsigned char)key, len);
		xorBuffer(keybuff, ciphertext, &plaintext, len);
		double score = scoreBuffer(plaintext, len);

		if (best > score)
		{
			best = score;
			foo = key;
		}
	
		delete [] plaintext;
		delete [] keybuff;
	}

	return foo;
}
