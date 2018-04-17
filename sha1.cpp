#include <cstring>
#include "sha1.h"

#define BUFFLEN 64
#define CircularShift(bits,word) (((word) << (bits)) | ((word) >> (32-(bits))))

SHA1::SHA1()
{
	h0 = 0x67452301;
	h1 = 0xEFCDAB89;
	h2 = 0x98BADCFE;
	h3 = 0x10325476;
	h4 = 0xC3D2E1F0;
	messageLen = 0;
	buff = new unsigned char[BUFFLEN];
	memset(buff, 0, BUFFLEN);
}

SHA1::~SHA1()
{
	delete [] buff;
}

void SHA1::update(const unsigned char* data, const unsigned int dataLen)
{
	for (unsigned int i = 0; i < dataLen; i++)
	{
		buff[(messageLen / 8) % BUFFLEN] = data[i];
		messageLen += 8;
		if (!((messageLen / 8) % BUFFLEN))
			updateInternalState();
	}
}

void SHA1::digest(unsigned char** digest, unsigned int* digestLen)
{
	*digestLen = SHA1_LENGTH;
	*digest = new unsigned char[*digestLen];
	unsigned char* pad = NULL;
	unsigned int padLen = 0;

	SHA1::calculatePad(messageLen, &pad, &padLen);
	update(pad, padLen);	
	
#if BYTE_ORDER == LITTLE_ENDIAN
	h0 = __builtin_bswap32(h0);
	h1 = __builtin_bswap32(h1);
	h2 = __builtin_bswap32(h2);
	h3 = __builtin_bswap32(h3);
	h4 = __builtin_bswap32(h4);
#endif

	memcpy(*digest, &h0, 4);
	memcpy(*digest + 4, (void*) &h1, 4);
	memcpy(*digest + 8, (void*) &h2, 4);
	memcpy(*digest + 12, (void*) &h3, 4);
	memcpy(*digest + 16, (void*) &h4, 4);

	delete [] pad;
}

void SHA1::spliceInState(const unsigned char* hash, const unsigned long messageLen)
{
	if (messageLen % 512)
		throw SHA1Exception("messageLen needs to be multiple of block size 512");
	this->messageLen = messageLen;
	
	memcpy(&h0, hash, 4);
	memcpy((void*) &h1, hash + 4, 4);
	memcpy((void*) &h2, hash + 8, 4);
	memcpy((void*) &h3, hash + 12, 4);
	memcpy((void*) &h4, hash + 16, 4);

#if BYTE_ORDER == LITTLE_ENDIAN
	h0 = __builtin_bswap32(h0);
	h1 = __builtin_bswap32(h1);
	h2 = __builtin_bswap32(h2);
	h3 = __builtin_bswap32(h3);
	h4 = __builtin_bswap32(h4);
#endif
}

/*
void SHA1::dumpState() const
{
	cout << hex << setw(8) << setfill('0') << h0 << endl;
	cout << hex << setw(8) << setfill('0') << h1 << endl;
	cout << hex << setw(8) << setfill('0') << h2 << endl;
	cout << hex << setw(8) << setfill('0') << h3 << endl;
	cout << hex << setw(8) << setfill('0') << h4 << endl;
}

void SHA1::dumpBuff() const
{
	for (unsigned int i = 0; i < BUFFLEN; i++)
	{
		if (!(i % 16 && i)) cout << endl;
		cout << hex << setw(2) << setfill('0') << (unsigned int)buff[i];
	}
	cout << endl;
}
*/

void SHA1::calculatePad(const unsigned long messageLen, unsigned char** pad, unsigned int* padLen)
{
	unsigned long ml = messageLen;
#if BYTE_ORDER == LITTLE_ENDIAN
	ml = __builtin_bswap64(ml);
#endif

	*padLen = 64 - ((messageLen / 8) % 64);
	*padLen += *padLen < 9 ? 64 : 0;
	
	*pad = new unsigned char[*padLen];
	memset(*pad, 0, *padLen);
	*pad[0] = '\x80';
	memcpy(*pad + *padLen - 8, &ml, sizeof(ml));
}

void SHA1::updateInternalState()
{
	unsigned int a = h0;
	unsigned int b = h1;
	unsigned int c = h2;
	unsigned int d = h3;
	unsigned int e = h4;
	unsigned int* w = new unsigned int[80];

	for (unsigned int i = 0; i < 16; i++)
	{
		w[i] = buff[i * 4] << 24;
		w[i] |= buff[i * 4 + 1] << 16;
		w[i] |= buff[i * 4 + 2] << 8;
		w[i] |= buff[i * 4 + 3];
	}

	for (unsigned i = 16; i < 80; i++)
		w[i] = CircularShift(1, w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]);

	for (unsigned int i = 0; i < 80; i++)
	{
		unsigned int temp;
		if (0 <= i && i <= 19)
			temp = CircularShift(5, a) + ((b & c) | ((~b) & d)) + e + w[i] + 0x5A827999;
		else if (20 <= i && i <= 39)
			temp = CircularShift(5, a) + (b ^ c ^ d) + e + w[i] + 0x6ED9EBA1;
		else if (40 <= i && i <= 59)
			temp = CircularShift(5, a) + ((b & c) | (b & d) | (c & d)) + e + w[i] + 0x8F1BBCDC;
		else if (60 <= i && i <= 79)
			temp = CircularShift(5, a) + (b ^ c ^ d) + e + w[i] + 0xCA62C1D6;

		e = d;
		d = c;
		c = CircularShift(30, b);
		b = a;
		a = temp;
	}

	h0 += a;
	h1 += b;
	h2 += c;
	h3 += d;
	h4 += e;

	delete [] w;
}
