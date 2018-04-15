#include <cstring>
#include <fstream>
#include <string>
#include <vector>
#include "aes.h"
#include "ctr.h"
#include "encoders.h"
#include "xors.h"

#include <iostream>
using namespace std;

const static string strings[40] = {"SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==", "Q29taW5nIHdpdGggdml2aWQgZmFjZXM=", "RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==", "RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=", "SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk", "T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==", "T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=", "UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==", "QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=", "T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl", "VG8gcGxlYXNlIGEgY29tcGFuaW9u", "QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==", "QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=", "QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==", "QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=", "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=", "VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==", "SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==", "SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==", "VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==", "V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==", "V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==", "U2hlIHJvZGUgdG8gaGFycmllcnM/", "VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=", "QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=", "VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=", "V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=", "SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==", "U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==", "U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=", "VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==", "QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu", "SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=", "VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs", "WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=", "SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0", "SW4gdGhlIGNhc3VhbCBjb21lZHk7", "SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=", "VHJhbnNmb3JtZWQgdXR0ZXJseTo=", "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4="};
static unsigned char** cts = NULL;
static unsigned int* ctLens = NULL;

void base64DecodeAndCTREncrypt(const unsigned char* source, const unsigned int sourceLen, unsigned char** dest, unsigned int* destLen, const unsigned char* key, const unsigned char* nonce, const unsigned int keyLen);

void ctr19_performEncryptions()
{
	unsigned char* stringRaw = NULL;
	unsigned char* key = new unsigned char[16];
	unsigned char* nonce = new unsigned char[16];

	cts = new unsigned char*[40];
	ctLens = new unsigned int[40];
	genRandomAESKey(key, 16);
	memset(nonce, 0, 16);

	for (int i = 0; i < 40; i++)
	{
		from_base64((unsigned char*) strings[i].c_str(), &stringRaw, strings[i].length(), &ctLens[i]);
		cts[i] = new unsigned char[ctLens[i]];
		aesEncryptCTR(stringRaw, cts[i], key, nonce, ctLens[i], 16);

		delete [] stringRaw;
	}

	delete [] key;
	delete [] nonce;
}

void ctr19_destroy()
{
	for (unsigned int i = 0; i < 40; i++)
		delete [] cts[i];
	delete [] cts;
	delete [] ctLens;
}

void ctr19_attack()
{
	/*unsigned int length = ctLens[0];
	unsigned char** blocks = NULL;
	unsigned char* key = NULL;

	for (unsigned int i = 1; i < 40; i++)
		if (ctLens[i] < length)
			length = ctLens[i];

	key = new unsigned char[length];
	blocks = new unsigned char*[length];
	for (unsigned int i = 0; i < length; i++)
		blocks[i] = new unsigned char[40];

	for (unsigned int i = 0; i < length * 40; i++)
		blocks[i / 40][i % 40] = cts[i % 40][i / 40];
	
	for (unsigned int i = 0; i < length; i++)
	{
		key[i] = findRepeatingXORKey(blocks[i], 40);
	}








	for (unsigned int i = 0; i < length; i++)
		delete [] blocks[i];
	delete [] blocks;
	delete [] key;
	 */
}

void ctr20_encryptFromFile(const char* filename, unsigned char*** cts, unsigned int** ctLens, unsigned int* ctCount)
{
	ifstream fin(filename);
	string in;
	vector<unsigned char*> vec_cts;
	vector<unsigned int> vec_ctLens;
	unsigned char* key = new unsigned char[16];
	unsigned char* nonce = new unsigned char[16];

	genRandomAESKey(key, 16);
	memset(nonce, 0, 16);

	while (fin.good())
	{
		fin >> in;
		if (fin.good())
		{
			unsigned char* ct = NULL;
			unsigned int ctLen = 0;

			base64DecodeAndCTREncrypt((unsigned char*) in.c_str(), in.length(), &ct, &ctLen, key, nonce, 16);
			vec_cts.push_back(ct);
			vec_ctLens.push_back(ctLen);
		}
	}

	*ctCount = vec_cts.size();
	*cts = new unsigned char*[*ctCount];
	*ctLens = new unsigned int[*ctCount];

	for (unsigned int i = 0; i < *ctCount; i++)
	{
		(*ctLens)[i] = vec_ctLens[i];
		(*cts)[i] = vec_cts[i];
	}

	delete [] key;
	delete [] nonce;
}

void ctr20_attack(const unsigned char** cts, const unsigned int* ctLens, const unsigned int ctCount)
{
	unsigned int shortest = ctLens[0];
	unsigned char** blocks = NULL;
	unsigned char* keystream = NULL;

	for (unsigned int i = 0; i < ctCount; i++)
		if (shortest > ctLens[i])
			shortest = ctLens[i];

	blocks = new unsigned char*[shortest];
	for (unsigned int i = 0; i < shortest; i++)
		blocks[i] = new unsigned char[ctCount];

	for (unsigned int i = 0; i < shortest; i++)
		for (unsigned int j = 0; j < ctCount; j++)
			blocks[i][j] = cts[j][i];

	keystream = new unsigned char[shortest];
	for (unsigned int i = 0; i < shortest; i++)
		keystream[i] = findRepeatingXORKey(blocks[i], ctCount);

	for (unsigned int j = 0; j < ctCount; j++)
	{
		for (unsigned int i = 0; i < shortest; i++)
			cout << (char) (cts[j][i] ^ keystream[i]);
		cout << endl;
	}
	
	for (unsigned int i = 0; i < shortest; i++)
		delete [] blocks[i];
	delete [] blocks;
	delete [] keystream;
}

void base64DecodeAndCTREncrypt(const unsigned char* source, const unsigned int sourceLen, unsigned char** dest, unsigned int* destLen, const unsigned char* key, const unsigned char* nonce, const unsigned int keyLen)
{
	unsigned char* sourceRaw = NULL;
	from_base64(source, &sourceRaw, sourceLen, destLen);
	*dest = new unsigned char[*destLen];
	aesEncryptCTR(sourceRaw, *dest, key, nonce, *destLen, keyLen);
	delete [] sourceRaw;
}
