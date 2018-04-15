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
	complete = false;
	buff = new unsigned char[BUFFLEN];
	memset(buff, 0, BUFFLEN);
}

SHA1::~SHA1()
{
	delete [] buff;
}

void SHA1::update(const unsigned char* data, const unsigned int dataLen)
{
	if (complete)
		throw SHA1Exception("Already marked complete");

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
	if (complete)
		throw SHA1Exception("Already marked complete");

	*digestLen = SHA1_LENGTH;
	*digest = new unsigned char[*digestLen];
	unsigned long ml = this->messageLen;

	update((unsigned char*) "\x80", 1);
	while ((messageLen + 64) % 512)
		update((unsigned char*) "\x00", 1);

#if BYTE_ORDER == LITTLE_ENDIAN
	ml = __builtin_bswap64(ml);
#endif

	update((unsigned char*) &ml, sizeof (ml));

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

	complete = true;
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
