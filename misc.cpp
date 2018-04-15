#include <cstring>
#include <fstream>
#include <string>
#include "misc.h"

void readFromFile(const char* filename, unsigned char** dest, unsigned int* destLen)
{
	std::ifstream fin(filename);
	std::string in = "";
	unsigned char* buff = new unsigned char[128];

	while (!fin.eof())
	{
		fin.getline((char*)buff, 128);
		in +=(char*) buff;
	}
	
	*destLen = in.length();
	*dest = new unsigned char[*destLen];

	memcpy((*dest), in.c_str(), *destLen);

	delete [] buff;
}

bool searchForText(const unsigned char* haystack, const unsigned int haystacklen, const unsigned char* needle, const unsigned int needleLen)
{
	if (needleLen > haystacklen)
		return false;
	for (unsigned int i = 0; i <= haystacklen - needleLen; i++)
	{
		if (!memcmp((char*)(haystack + i), (char*)needle, needleLen))
			return true;
	}
	
	return false;
}

void encode(const unsigned char* source, const unsigned int sourceLen, unsigned char** dest, unsigned int* destLen)
{
	std::string foo = "";
	for (unsigned int i = 0; i < sourceLen; i++)
		foo += source[i];
	int pos = 0;
	while ((pos = foo.find(";")) != (int)std::string::npos)
		foo.replace(pos, 1, "%3B");
	while ((pos = foo.find("=")) != (int)std::string::npos)
		foo.replace(pos, 1, "%3D");

	*destLen = foo.length();
	*dest = new unsigned char[*destLen];

	memcpy(*dest, foo.c_str(), foo.length());
}
