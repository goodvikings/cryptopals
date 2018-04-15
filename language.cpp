#include "language.h"

// Relative frequencies		SPACE, A, B, ... Z
const static double english[] = {12.17, 06.09, 01.05, 02.84, 02.92, 11.36, 01.79, 01.38, 03.41, 05.44, 00.24, 00.41, 02.92, 02.76, 05.44, 06.00, 01.95, 00.24, 04.95, 05.68, 08.03, 02.43, 00.97, 01.38, 00.24, 01.30, 00.03};

double scoreBuffer(const unsigned char* source, const unsigned int len)
{
	unsigned int unprintables = 0;
	double counts[27] = {};
	double score = 0;

	for (unsigned int i = 0; i < len; i++)
	{
		if (source[i] == ' ')
		{
			counts[0]++;
			continue;
		}
		if (source[i] > 128 || source[i] < 32)
		{
			unprintables++;
			continue;
		}
		if (source[i] >= 'a' && source[i] <= 'z')
		{
			counts[source[i] - 'a' + 1]++;
			continue;
		}
		if (source[i] >= 'A' && source[i] <= 'Z')
		{
			counts[source[i] - 'A' + 1]++;
			continue;
		}
	}

	for (unsigned int i = 0; i < 27; i++)
	{
		counts[i] /= len; // percentage chance of each letter in the sample text
		score += (english[i] - counts[i]) * (english[i] - counts[i]);
	}

	return (score / len) + (unprintables * unprintables);
}

unsigned int hammingDiffernece(const unsigned char* foo, const unsigned char* bar, const unsigned int len)
{
	unsigned int score = 0;
	for (unsigned int i = 0; i < len; i++)
	{
		score += __builtin_popcount(foo[i] ^ bar[i]);
	}
	return score;
}

unsigned int countZeroHammings(const unsigned char* buff, const unsigned int len, const unsigned int blockLen)
{
	unsigned int count = 0;

	for (unsigned int i = 0; i < len / blockLen; i++)
	{
		for (unsigned int j = i + 1; j < len / blockLen; j++)
		{
			if (!hammingDiffernece(buff + (i * blockLen), buff + (j * blockLen), blockLen))
			{
				count++;
			}
		}
	}

	return count;
}
