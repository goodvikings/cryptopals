#ifndef SRP_H
#define SRP_H

#include <gmpxx.h>
#include "mt19937.h"
#include "dh.h"

const mpz_class srp_N("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16);
const mpz_class srp_g("2");
const mpz_class srp_k("3");
const char user[] = "herp@derp.com";
const unsigned int userLen = strlen(user);
const char pass[] = "supersecretpass";
const unsigned int passLen = strlen(pass);

class SRPServer
{
public:
	SRPServer();
	~SRPServer();
	void step1();
	void recvClientStep1(const mpz_class* pub, const char* email);
	void sendSaltAndPub(unsigned int* salt, mpz_class* pub);
private:
	unsigned int salt;
	mt19937* generator;
	mpz_class* v;
	mpz_class* client_pub;
	dhSet* dh;
	
	char* email = NULL;
};

class SRPClient
{
public:
	SRPClient();
	~SRPClient();
	void step1(mpz_class* A, char** email);
private:
	mt19937* generator;
	dhSet* dh;
};

#endif
