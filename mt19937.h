#ifndef MT19937_H
#define MT19937_H

#include <string>
#include "exception.h"

#define MT_SIZE 624

class mt19937
{
public:
	mt19937();
	mt19937(const int seed);
	~mt19937();
	void seed();
	void seed(const int seed);
	unsigned int getRand32();
	void spliceInState(const unsigned int* state);
private:
	void generate();
	unsigned int* state;
	unsigned int current;
	bool seeded;
};

#endif