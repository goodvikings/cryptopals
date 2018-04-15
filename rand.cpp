#include <stdlib.h>
#include <time.h>

static bool seeded = false;

void seedRand()
{
	if (!seeded) srand(time(0));
}
