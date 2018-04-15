#ifndef KVPAIR_H
#define KVPAIR_H

#include <string>
using namespace std;

class kvpair
{
public:
	string key;
	string value;
	kvpair();
	kvpair(const kvpair* other);
	kvpair(const string key, const string value);
	kvpair(const char* key, const char* value);
	~kvpair();
};

#endif