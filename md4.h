#ifndef MD4_H
#define MD4_H

#include <openssl/md4.h>
#include <string>
#include "exception.h"

#define MD4_LENGTH 16

class MD4Exception : public Exception
{
public:

	MD4Exception(std::string reason) : Exception(reason)
	{
	};
};

class md4
{
public:
	md4();
	~md4();
	void update(const unsigned char* data, const unsigned int dataLen);
	void digest(unsigned char** digest, unsigned int* digestLen);
	void spliceInState(const unsigned char* hash, const unsigned long messageLen);

//	void dumpState() const;
//	void dumpBuff() const;

private:
	MD4_CTX* ctx;
};

#endif