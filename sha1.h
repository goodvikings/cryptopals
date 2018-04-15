#ifndef SHA1_H
#define SHA1_H

#include <string>
#include "exception.h"

#define SHA1_LENGTH 20

class SHA1Exception : public Exception
{
public:
	SHA1Exception(std::string reason) : Exception(reason) {};	
};

class SHA1
{
public:
	SHA1();
	~SHA1();
	void update(const unsigned char* data, const unsigned int dataLen);
	void digest(unsigned char** digest, unsigned int* digestLen);
private:
	void updateInternalState();

	bool complete;
	unsigned int h0, h1, h2, h3, h4;
	unsigned long messageLen;
	unsigned char* buff;
};

#endif