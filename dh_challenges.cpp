#include <cstdlib>
#include <gmpxx.h>
#include "dh.h"
#include "dh_challenges.h"

#include <iostream>
using namespace std;

void challenge_33()
{
	mpz_class p("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16);
	mpz_class g("2"), pa, pb;
	mt19937 generator;
	dhSet A, B;

	generator.seed();

	A.applyParams(&p, &g);
	A.generateKeys(&generator);
	pa = A.getPub();

	// A->B - Send "p", "g", "A"
	B.applyParams(&p, &g);
	B.generateKeys(&generator);
	pb = B.getPub();

	//B->A - Send "B"
	A.calculateShared(&pb);
	B.calculateShared(&pa);

	unsigned char* a_iv = NULL;
	unsigned char* a_ct = NULL;
	unsigned int a_ctLen = 0;
	unsigned char* b_plain = NULL;
	unsigned int b_plainLen = 0;

	// A->B - Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
	A.sendEncMessage((unsigned char*) "abc", 3, &a_iv, &a_ct, &a_ctLen);
	B.recvEndMessage(a_ct, a_ctLen, a_iv, &b_plain, &b_plainLen);

	// B->A - Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
	unsigned char* b_iv = NULL;
	unsigned char* b_ct = NULL;
	unsigned int b_ctLen = 0;
	unsigned char* a_plain = NULL;
	unsigned int a_plainLen = 0;

	B.sendEncMessage(b_plain, b_plainLen, &b_iv, &b_ct, &b_ctLen);
	A.recvEndMessage(b_ct, b_ctLen, b_iv, &a_plain, &a_plainLen);

	delete [] a_iv;
	delete [] a_ct;
	delete [] b_plain;
	delete [] b_iv;
	delete [] b_ct;
	delete [] a_plain;
}

void challenge_34()
{
	mpz_class p("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16);
	mpz_class g("2"), pa, pb;
	mt19937 generator;
	dhSet A, B, Ma;

	generator.seed();

	A.applyParams(&p, &g);
	A.generateKeys(&generator);
	pa = A.getPub();

	//A->M Send "p", "g", "A"
	//M->B Send "p", "g", "p"
	B.applyParams(&p, &g);
	B.generateKeys(&generator);
	pb = B.getPub();
	B.calculateShared(&p);

	//B->M Send "B"
	//M->A Send "p"
	A.calculateShared(&p);

	Ma.applyParams(&p, &g);
	Ma.generateKeys(&generator);
	Ma.calculateShared(&p);

	//A->M Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
	//M->B Relay that to B
	unsigned char* a_iv = NULL;
	unsigned char* a_ct = NULL;
	unsigned int a_ctLen = 0;
	unsigned char* b_plain = NULL;
	unsigned int b_plainLen = 0;
	unsigned char* m_plain = NULL;
	unsigned int m_plainLen = 0;
	A.sendEncMessage((unsigned char*) "ABC", 3, &a_iv, &a_ct, &a_ctLen);
	B.recvEndMessage(a_ct, a_ctLen, a_iv, &b_plain, &b_plainLen);
	Ma.recvEndMessage(a_ct, a_ctLen, a_iv, &m_plain, &m_plainLen);

	//B->M Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
	//M->A Relay that to A
	unsigned char* b_iv = NULL;
	unsigned char* b_ct = NULL;
	unsigned int b_ctLen = 0;
	unsigned char* a_plain = NULL;
	unsigned int a_plainLen = 0;
	B.sendEncMessage(b_plain, b_plainLen, &b_iv, &b_ct, &b_ctLen);
	A.recvEndMessage(b_ct, b_ctLen, b_iv, &a_plain, &a_plainLen);

	delete [] m_plain;
	Ma.recvEndMessage(b_ct, b_ctLen, b_iv, &m_plain, &m_plainLen);

	delete [] a_iv;
	delete [] a_ct;
	delete [] b_plain;
	delete [] b_iv;
	delete [] b_ct;
	delete [] a_plain;
	delete [] m_plain;
}

void challenge_35(const mpz_class* p, const mpz_class* g)
{
	mpz_class pa, pb;
	mt19937 generator;
	dhSet A, B, Ma;

	generator.seed();

	A.applyParams(p, g);
	A.generateKeys(&generator);
	pa = A.getPub();

	//A->M Send "p", "g", "A"
	//M->B Send "p", "g", "p"
	B.applyParams(p, g);
	B.generateKeys(&generator);
	pb = B.getPub();
	B.calculateShared(p);

	//B->M Send "B"
	//M->A Send "p"
	A.calculateShared(p);

	Ma.applyParams(p, g);
	Ma.generateKeys(&generator);
	Ma.calculateShared(p);

	//A->M Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
	//M->B Relay that to B
	unsigned char* a_iv = NULL;
	unsigned char* a_ct = NULL;
	unsigned int a_ctLen = 0;
	unsigned char* b_plain = NULL;
	unsigned int b_plainLen = 0;
	unsigned char* m_plain = NULL;
	unsigned int m_plainLen = 0;
	A.sendEncMessage((unsigned char*) "ABC", 3, &a_iv, &a_ct, &a_ctLen);
	B.recvEndMessage(a_ct, a_ctLen, a_iv, &b_plain, &b_plainLen);
	Ma.recvEndMessage(a_ct, a_ctLen, a_iv, &m_plain, &m_plainLen);

	//B->M Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
	//M->A Relay that to A
	unsigned char* b_iv = NULL;
	unsigned char* b_ct = NULL;
	unsigned int b_ctLen = 0;
	unsigned char* a_plain = NULL;
	unsigned int a_plainLen = 0;
	B.sendEncMessage(b_plain, b_plainLen, &b_iv, &b_ct, &b_ctLen);
	A.recvEndMessage(b_ct, b_ctLen, b_iv, &a_plain, &a_plainLen);

	delete [] m_plain;
	Ma.recvEndMessage(b_ct, b_ctLen, b_iv, &m_plain, &m_plainLen);
	
	delete [] a_iv;
	delete [] a_ct;
	delete [] b_plain;
	delete [] b_iv;
	delete [] b_ct;
	delete [] a_plain;
	delete [] m_plain;	
}
