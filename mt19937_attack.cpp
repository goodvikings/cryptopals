#include <cstdlib>
#include <time.h>
#include "mt19937.h"
#include "mt19937_attack.h"

unsigned int unTemper(const unsigned int foo);

unsigned int mtGenerateFromUnknownTimestamp()
{
	srand(time(0));

	unsigned int seed = time(0) + (rand() % 960) + 40;

	mt19937 mt(seed);

	return mt.getRand32();
}

unsigned int discoverSeed(const unsigned int val)
{
	unsigned int t = time(0);
	mt19937 mt;

	for (unsigned int i = t + 5000; i > t - 5000; i--)
	{
		mt.seed(i);
		if (mt.getRand32() == val)
			return i;
	}

	return 0;
}

void cloneMT(mt19937* source, mt19937* dest)
{
	unsigned int* dupeState = new unsigned int[MT_SIZE];
	for (unsigned int i = 0; i < MT_SIZE; i++)
		dupeState[i] = unTemper(source->getRand32());
	dest->spliceInState(dupeState);
	delete [] dupeState;	
}

unsigned int unTemper(const unsigned int foo)
{
	/*
	 temper function is:
	unsigned int y = this->state[current];
	y = y ^ (y >> 11);
	y = y ^ ((y << 7) & MT_SB_COEF);
	y = y ^ ((y << 15) & MT_TC_COEF);
	y = y ^ (y >> 18);
	 */
	// shamelessly stolen, no idea how this works. 
	unsigned int y = foo;
	y = y ^ (y >> 18);
	y = y ^ ((y & 0x1df8c) << 15);
	unsigned int t = y;
	t = ((t & 0x0000002d) << 7) ^ y;
	t = ((t & 0x000018ad) << 7) ^ y;
	t = ((t & 0x001a58ad) << 7) ^ y;
	y = ((t & 0x013a58ad) << 7) ^ y;
	unsigned int top = y & 0xffe00000;
	unsigned int mid = y & 0x001ffc00;
	unsigned int low = y & 0x000003ff;
	return top | ((top >> 11) ^ mid) | ((((top >> 11) ^ mid) >> 11) ^ low);
}
