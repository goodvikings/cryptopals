#ifndef DH_H
#define DH_H

#include <gmpxx.h>
#include "exception.h"
#include "mt19937.h"

class DHSetException : public Exception
{
public:
	DHSetException(std::string reason) : Exception(reason) {};
};

class dhSet
{
public:
	dhSet();
	~dhSet();
	void applyParams(const mpz_class* prime, const mpz_class* g);
	void generateKeys(mt19937* generator);
	void calculateShared(const mpz_class* otherPub) const;
	mpz_class getPub() const;
	void sendEncMessage(const unsigned char* message, const unsigned int messageLen, unsigned char** iv, unsigned char** out, unsigned int* outLen) const;
	void recvEndMessage(const unsigned char* ct, const unsigned int ctLen, const unsigned char* iv, unsigned char** out, unsigned int* outLen) const;
private:
	bool paramSet;
	bool keysSet;
	mpz_class* prime;
	mpz_class* generator;
	mpz_class* pub;
	mpz_class* priv;
	unsigned char* secret;
};

#endif