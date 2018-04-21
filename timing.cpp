#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/time.h>
#include "misc.h"
#include "timing.h"

#include <iostream>
using namespace std;

#define toHexChar(a) a < 10 ? a + '0' : a + 'a' - 10

unsigned char findNextChar(const unsigned char* base, const unsigned int baseLen, const unsigned char* known, const unsigned int knownLen);
void buildUrl(const unsigned char* base, const unsigned int baseLen, const unsigned char* known, const unsigned int knownLen, unsigned char** result, unsigned int* resultLen);

void timingAttack31(const unsigned char* urlBase, unsigned char** sig, unsigned int* sigLen)
{
	bool found = false;
	std::string known = "";
	unsigned char* buff = NULL;
	unsigned int buffLen = 0;
	
	for (unsigned int i = 0; i < 512 && !found; i++)
	{
		buildUrl(urlBase, strlen((char*)urlBase), (unsigned char*)known.c_str(), known.length(), &buff, &buffLen);
		buff[buffLen - 2] = 0;
		if (curl(buff) == 200)
			break;

		
		unsigned char foo = findNextChar(urlBase, strlen((char*)urlBase), (unsigned char*)known.c_str(), known.length());
		known += foo;
		cout << foo << endl;
	}
	
	cout << endl;
	
	*sigLen = known.length();
	*sig = new unsigned char[*sigLen];
	memcpy(*sig, known.c_str(), *sigLen);
}

unsigned char findNextChar(const unsigned char* base, const unsigned int baseLen, const unsigned char* known, const unsigned int knownLen)
{
	unsigned int* times = new unsigned int[16];
	unsigned char* url = NULL;
	unsigned int urlLen = 0;
	timeval start, end;
	unsigned char result = 0;
	
	memset(times, 0, sizeof(unsigned int) * 16);
	buildUrl(base, baseLen, known, knownLen, &url, &urlLen);
	url[urlLen - 1] = 0;
	
	for (unsigned int i = 0; i < 16; i++)
	{
		url[urlLen - 2] = toHexChar(i);
		
		unsigned int avg = 0;
		
		for (unsigned int j = 0; j < 5; j++) // added in for challenge 32
		{
			gettimeofday(&start, 0);
			curl(url);
			gettimeofday(&end, 0);
			avg += (end.tv_sec - start.tv_sec) * 1000000 + end.tv_usec - start.tv_usec;
		}
		
		times[i] = avg / 5;
	}
	
	result = 0;
	for (unsigned int i = 1; i < 16; i++)
		if (times[result] < times[i])
			result = i;
	
	delete [] url;
	delete [] times;
		
	return toHexChar(result);
}

/**
 * base should be full url, only missing the sig
 * resultLen will have room for another character to append, and the trailing null byte
 */
void buildUrl(const unsigned char* base, const unsigned int baseLen, const unsigned char* known, const unsigned int knownLen, unsigned char** result, unsigned int* resultLen)
{
	*resultLen = baseLen + knownLen + 2;
	*result = new unsigned char[*resultLen];

	memcpy(*result, base, baseLen);
	memcpy(*result + baseLen, known, knownLen);
}
