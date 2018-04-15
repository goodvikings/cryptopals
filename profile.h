#ifndef PROFILE_H
#define PROFILE_H

#include <vector>
#include "kvpair.h"
using namespace std;

class profile
{
private:
	vector<kvpair> pairs;
public:
	profile();
	profile(const char* encoded, const unsigned int encodedLen);
	void fromEncoded(const char* encoded, const unsigned int encodedLen);
	void profileFor(const char* email, const unsigned int emailLen);
	const string toEncodedString();
	const string toString();
	const void encrypt(unsigned char** dest, unsigned int* destLen);
	void decrypt(const unsigned char* source, const unsigned int sourceLen);
};

#endif