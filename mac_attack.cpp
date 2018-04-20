#include <cstdlib>
#include <cstring>
#include "sha1.h"
#include "mac.h"
#include "mac_attack.h"
#include "md4.h"

void sha1_mac_attack(const unsigned char* origMessage, const unsigned int origMessageLen, const unsigned char* toAppend, const unsigned int toAppendLen, const unsigned char* origMac, unsigned char** resultMessage, unsigned int* resultMessageLen, unsigned char** resultMac)
{
	bool found = false;
	for (unsigned int i = 16; i < 17 && !found; i++) // secret key length brute force
	{
		unsigned char* pad = NULL;
		unsigned int padLen = 0;
		unsigned int poisonedMacLen = 0;
		SHA1 digestor;

		SHA1::calculatePad((origMessageLen + i) * 8, &pad, &padLen);

		*resultMessageLen = origMessageLen + padLen + toAppendLen;
		*resultMessage = new unsigned char[*resultMessageLen];

		memcpy(*resultMessage, origMessage, origMessageLen);
		memcpy(*resultMessage + origMessageLen, pad, padLen);
		memcpy(*resultMessage + origMessageLen + padLen, toAppend, toAppendLen);

		digestor.spliceInState(origMac, (origMessageLen + padLen + i) * 8);
		digestor.update(toAppend, toAppendLen);
		digestor.digest(resultMac, &poisonedMacLen);

		if (verifySHA1Mac(*resultMessage, *resultMessageLen, *resultMac, poisonedMacLen)) // internal buffer for poisoned mac includes 
			found = true;

		delete [] pad;
	}
}

void md4_mac_attack(const unsigned char* origMessage, const unsigned int origMessageLen, const unsigned char* toAppend, const unsigned int toAppendLen, const unsigned char* origMac, unsigned char** resultMessage, unsigned int* resultMessageLen, unsigned char** resultMac)
{
	bool found = false;
	for (unsigned int i = 16; i < 17 && !found; i++) // secret key length brute force
	{
		unsigned char* pad = NULL;
		unsigned int padLen = 0;
		unsigned int poisonedMacLen = 0;
		md4 digestor;

		SHA1::calculatePad((origMessageLen + i) * 8, &pad, &padLen);

		*resultMessageLen = origMessageLen + padLen + toAppendLen;
		*resultMessage = new unsigned char[*resultMessageLen];

		memcpy(*resultMessage, origMessage, origMessageLen);
		memcpy(*resultMessage + origMessageLen, pad, padLen);
		memcpy(*resultMessage + origMessageLen + padLen, toAppend, toAppendLen);

		digestor.spliceInState(origMac, (origMessageLen + padLen + i) * 8);
		digestor.update(toAppend, toAppendLen);
		digestor.digest(resultMac, &poisonedMacLen);

		if (verifySHA1Mac(*resultMessage, *resultMessageLen, *resultMac, poisonedMacLen)) // internal buffer for poisoned mac includes 
			found = true;

		delete [] pad;
	}
}
