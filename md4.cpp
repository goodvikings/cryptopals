#include <cstring>
#include <openssl/md4.h>
#include "md4.h"

md4::md4()
{
	this->ctx = new MD4_CTX;
	MD4_Init(this->ctx);
}

md4::~md4()
{
	delete ctx;
}

void md4::update(const unsigned char* data, const unsigned int dataLen)
{
	MD4_Update(this->ctx, data, dataLen);
}

void md4::digest(unsigned char** digest, unsigned int* digestLen)
{
	*digestLen = MD4_DIGEST_LENGTH;
	*digest = new unsigned char[MD4_DIGEST_LENGTH];

	MD4_Final(*digest, this->ctx);
}

void md4::spliceInState(const unsigned char* hash, const unsigned long messageLen)
{
	this->ctx->Nh = messageLen >> 32;
	this->ctx->Nl = messageLen & 0xFFFFFFFF;
	
	memcpy((void*) &ctx->A, hash, 4);
	memcpy((void*) &ctx->B, hash + 4, 4);
	memcpy((void*) &ctx->C, hash + 8, 4);
	memcpy((void*) &ctx->D, hash + 12, 4);

#if BYTE_ORDER == BIG_ENDIAN
	ctx->A = __builtin_bswap32(ctx->A);
	ctx->B = __builtin_bswap32(ctx->B);
	ctx->C = __builtin_bswap32(ctx->C);
	ctx->D = __builtin_bswap32(ctx->D);
#endif
}

/*void md4::dumpState() const
{
	cout << hex << setw(2) << setfill('0') << this->ctx->A << endl;
	cout << hex << setw(2) << setfill('0') << this->ctx->B << endl;
	cout << hex << setw(2) << setfill('0') << this->ctx->C << endl;
	cout << hex << setw(2) << setfill('0') << this->ctx->D << endl;
}

void md4::dumpBuff() const
{

}*/
