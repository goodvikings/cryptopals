#ifndef PKCS7_H
#define PKCS7_H

#include <string>
#include "exception.h"

class PKCS7Exception : public Exception
{
public:
	PKCS7Exception(std::string reason) : Exception(reason) {};
};

void addPKCS7Pad(const unsigned char* source, unsigned char** dest, const unsigned int sourceLen, const unsigned int destLen);
void removePCKSPad(const unsigned char* source, unsigned char** dest, const unsigned int sourceLen, unsigned int* destLen, const unsigned int blocksize);

#endif