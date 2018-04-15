#include <string>
#include "kvpair.h"
using namespace std;

kvpair::kvpair()
{
// empty contructor
}

kvpair::kvpair(const kvpair* other)
{
	this->key = string(other->key);
	this->value = string(other->value);
}

kvpair::kvpair(const string key, const string value)
{
	this->key = string(key);
	this->value = string(value);
}

kvpair::kvpair(const char* key, const char* value)
{
	this->key = string(key);
	this->value = string(value);
}

kvpair::~kvpair()
{
// empty destructor
}

