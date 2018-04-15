#ifndef AES_H
#define AES_H

#include <string>
#include <openssl/aes.h>
#include "exception.h"

class AESException : public Exception
{
public:
	AESException(std::string reason) : Exception(reason) {};
};

void seedRand();
void genRandomAESKey(unsigned char* bytes, unsigned int length);
void aesEncryptECB(const unsigned char* source, unsigned char* dest, const unsigned char* key, const unsigned int sourceLen, const unsigned int keyLen);
void aesDecryptECB(const unsigned char* source, unsigned char* dest, const unsigned char* key, const unsigned int sourceLen, const unsigned int keyLen);
void aesEncryptCBC(const unsigned char* source, unsigned char* dest, const unsigned char* key, const unsigned char* iv, const unsigned int sourceLen, const unsigned int keyLen);
void aesDecryptCBC(const unsigned char* source, unsigned char* dest, const unsigned char* key, const unsigned char* iv, const unsigned int sourceLen, const unsigned int keyLen);
void aesEncryptCTR(const unsigned char* source, unsigned char* dest, const unsigned char* key, const unsigned char* nonce, const unsigned int sourceLen, const unsigned int keyLen);
void aesDecryptCTR(const unsigned char* source, unsigned char* dest, const unsigned char* key, const unsigned char* nonce, const unsigned int sourceLen, const unsigned int keyLen);
void aesEncryptBlock(const unsigned char* source, unsigned char* dest, const AES_KEY* k);
void aesDecryptBlock(const unsigned char* source, unsigned char* dest, const AES_KEY* k);

void challenge11(const unsigned char* source, unsigned char** dest, const unsigned int sourceLen, unsigned int* destLen);

#endif