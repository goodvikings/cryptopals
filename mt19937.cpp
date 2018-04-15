#include <cstring>
#include <time.h>
#include "mt19937.h"

#define MT_32B_MASK 0xFFFFFFFFUL
#define MT_INIT_COEF 0x6C078965UL
#define MT_SB_COEF 0x9D2C5680UL
#define MT_TC_COEF 0xEFC60000UL

mt19937::mt19937()
{
	this->seeded = false;
	this->current = 0;
	this->state = NULL;
}

mt19937::mt19937(const int seed)
{
	this->seeded = false;
	this->current = 0;
	this->state = NULL;
	this->seed(seed);
}

mt19937::~mt19937()
{
	delete [] this->state;
	this->state = NULL;
}

void mt19937::seed()
{
	this->seed(time(0));
}

void mt19937::seed(const int seed)
{
	if (this->state)
	{
		delete [] this->state;
		this->state = NULL;
	}
	
	this->seeded = true;
	this->state = new unsigned int[MT_SIZE];
	this->state[0] = seed;

	for (unsigned int i = 1; i < MT_SIZE; i++)
		this->state[i] = (MT_INIT_COEF * (this->state[i - 1] ^ (this->state[i - 1] >> 30)) + i) & MT_32B_MASK;

	this->current = 0;
}

unsigned int mt19937::getRand32()
{
	if (this->current == 0)
		generate();

	unsigned int y = this->state[current];
	y = y ^ (y >> 11);
	y = y ^ ((y << 7) & MT_SB_COEF);
	y = y ^ ((y << 15) & MT_TC_COEF);
	y = y ^ (y >> 18);

	current = (current + 1) % MT_SIZE;

	return y;
}

void mt19937::generate()
{
	for (unsigned int i = 0; i < MT_SIZE; i++)
	{
		unsigned int y = (this->state[i] & 0x80000000) | (this->state[(i + 1) % 624] & 0x7FFFFFFF);
		this->state[i] = this->state[(i + 397) % 624] ^ (y >> 1);
		if ((y % 2) != 0)
			this->state[i] = this->state[i] ^ 0x9908B0DF;
	}
}

void mt19937::spliceInState(const unsigned int* state)
{
	this->seeded = true;
	if (!this->state)
		this->state = new unsigned int[MT_SIZE];
	memcpy(this->state, state, MT_SIZE * sizeof(unsigned int));
}
