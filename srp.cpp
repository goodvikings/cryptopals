#include <openssl/sha.h>
#include "mt19937.h"
#include "srp.h"

#include <iostream>
using namespace std;

#define SHA256ToGMP(mpz_ptr, buff_ptr) mpz_import(mpz_ptr->get_mpz_t(), SHA256_DIGEST_LENGTH, 0, 1, 0, 0, buff_ptr)

SRPServer::SRPServer()
{
	salt = 0;
	generator = new mt19937();
	v = new mpz_class;
	dh = new dhSet;

	generator->seed();

	dh->applyParams(&srp_N, &srp_g);
	dh->generateKeys(generator);
}

SRPServer::~SRPServer()
{
	delete generator;
	delete v;
	delete dh;
	if (email) delete [] email;
	if (client_pub) delete client_pub;
}

void SRPServer::step1()
{
	SHA256_CTX sha;
	unsigned char* hash = new unsigned char[SHA256_DIGEST_LENGTH];
	mpz_class* hashInt = new mpz_class;

	SHA256_Init(&sha);

	salt = generator->getRand32();

	SHA256_Update(&sha, &salt, sizeof (salt));
	SHA256_Final(hash, &sha);

	SHA256ToGMP(hashInt, hash);
	mpz_powm(v->get_mpz_t(), srp_g.get_mpz_t(), hashInt->get_mpz_t(), srp_N.get_mpz_t());

	delete hashInt;
	delete [] hash;
}

void SRPServer::recvClientStep1(const mpz_class* pub, const char* email)
{	
	if (this->email) delete [] email;
	client_pub = new mpz_class;
	*client_pub = *pub;
	this->email = new char[userLen];
	memcpy(this->email, email, userLen);
}

void SRPServer::sendSaltAndPub(unsigned int* salt, mpz_class* pub)
{
	*salt = this->salt;
	*pub = (srp_k * *v) + dh->getPub();
}

SRPClient::SRPClient()
{
	dh = new dhSet;
	generator = new mt19937;

	generator->seed();

	dh->applyParams(&srp_N, &srp_g);
	dh->generateKeys(generator);
}

SRPClient::~SRPClient()
{
	delete generator;
	delete dh;
}

void SRPClient::step1(mpz_class* A, char** email)
{
	*A = dh->getPub();
	*email = new char[userLen];
	memcpy(*email, user, userLen);
}
