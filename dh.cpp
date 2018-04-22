#include <gmpxx.h>
#include "aes.h"
#include "dh.h"
#include "mt19937.h"
#include "sha1.h"
#include "pkcs7.h"

#include <iostream>
using namespace std;

void generateDHShared(const mpz_class* p, const mpz_class* a, const mpz_class* B, mpz_class* s);

dhSet::dhSet()
{
	paramSet = false;
	keysSet = false;
	this->prime = new mpz_class;
	this->generator = new mpz_class;
	this->pub = new mpz_class;
	this->priv = new mpz_class;
	this->secret = new unsigned char[16];
}

dhSet::~dhSet()
{
	delete this->prime;
	delete this->generator;
	delete this->pub;
	delete this->priv;
	delete [] this->secret;
}

void dhSet::applyParams(const mpz_class* prime, const mpz_class* g)
{
	if (*prime == 0 || *g == 0)
		throw DHSetException("Invalid params");

	*this->prime = *prime;
	*this->generator = *g;

	paramSet = true;
}

void dhSet::generateKeys(mt19937* generator)
{
	if (!paramSet)
		throw DHSetException("Params not set");

	(*this->priv) = 0;
	while ((*this->priv) == 0)
	{
		while ((*this->priv) < (*this->prime))
		{
			*this->priv |= generator->getRand32();
			*this->priv <<= 32;
		}
		*this->priv %= *this->prime;
	}

	mpz_powm(this->pub->get_mpz_t(), this->generator->get_mpz_t(), this->priv->get_mpz_t(), this->prime->get_mpz_t());

	keysSet = true;
}

mpz_class dhSet::getPub() const
{
	mpz_class r = *this->pub;
	return r;
}

void dhSet::calculateShared(const mpz_class* otherPub) const
{
	mpz_class s;
	mpz_powm(s.get_mpz_t(), otherPub->get_mpz_t(), priv->get_mpz_t(), prime->get_mpz_t());

	unsigned int size = 1;
	unsigned int numb = 8 * size;
	unsigned int count = (mpz_sizeinbase(s.get_mpz_t(), 2) + numb - 1) / numb;
	unsigned char* buff = new unsigned char[count * size];
	unsigned long buffLen = 0;
	unsigned char* hash = NULL;
	unsigned int hashLen = 0;
	SHA1 digestor;

	mpz_export(buff, &buffLen, 1, size, 1, 0, s.get_mpz_t());

	digestor.update(buff, buffLen);
	digestor.digest(&hash, &hashLen);

	memcpy(this->secret, hash, 16);

//	for (unsigned int i = 0 ; i < 16; i++)
//		cout << secret[i];
	
	delete [] hash;
	delete [] buff;
}

void dhSet::sendEncMessage(const unsigned char* message, const unsigned int messageLen, unsigned char** iv, unsigned char** out, unsigned int* outLen) const
{
	unsigned char* padded = NULL;
	
	*iv = new unsigned char[16];
	genRandomAESKey(*iv, 16);

	*outLen = ((messageLen / 16) + 1) * 16;
	*out = new unsigned char[*outLen];	
	
	addPKCS7Pad(message, &padded, messageLen, *outLen);
	
	aesEncryptCBC(padded, *out, this->secret, *iv, *outLen, 16); 	
	
	delete [] padded;
}

void dhSet::recvEndMessage(const unsigned char* ct, const unsigned int ctLen, const unsigned char* iv, unsigned char** out, unsigned int* outLen) const
{
	unsigned char* padded = new unsigned char[ctLen];
	
	aesDecryptCBC(ct, padded, this->secret, iv, ctLen, 16);
	removePCKSPad(padded, out, ctLen, outLen, 16);
	
	delete [] padded;
}
