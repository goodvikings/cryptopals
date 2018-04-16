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
	void spliceInState(const unsigned char* hash);

//	void dumpState() const;
//	void dumpBuff() const;
	
	static void calculatePad(const unsigned long messageLen, unsigned char** pad, unsigned int* padLen);
private:
	void updateInternalState();

	bool complete;
	unsigned int h0, h1, h2, h3, h4;
	unsigned long messageLen;
	unsigned char* buff;
};

#endif