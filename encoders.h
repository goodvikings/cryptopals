#ifndef ENCODERS_H
#define ENCODERS_H

#include <string>
#include "exception.h"

class EncoderException : public Exception
{
public:
	EncoderException(std::string reason) : Exception(reason) {};
};

void to_hex(const unsigned char* source, unsigned char** dest, const unsigned int sourceLen, unsigned int* destLen);
void from_hex(const unsigned char* source, unsigned char** dest, const unsigned int sourceLen, unsigned int* destLen);
void to_base64(const unsigned char* source, unsigned char** dest, const unsigned int sourceLen, unsigned int* destLen);
void from_base64(const unsigned char* source, unsigned char** dest, const unsigned int sourceLen, unsigned int* destLen);

#endif