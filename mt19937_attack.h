#ifndef MT19937_ATTACK_H
#define MT19937_ATTACK_H

#include "mt19937.h"

unsigned int mtGenerateFromUnknownTimestamp();
unsigned int discoverSeed(const unsigned int val);
//unsigned int unTemper(const unsigned int foo);
void cloneMT(mt19937* source, mt19937* dest);

#endif