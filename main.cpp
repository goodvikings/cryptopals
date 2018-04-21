#include <cstring>
#include <iostream>

#include "misc.h"
//#include <iomanip>
//#include "aes.h"
//#include "ctr.h"
//#include "encoders.h"
//#include "misc.h"
//#include "mt19937.h"
//#include "mt19937_attack.h"
//#include "mt19937_cipher.h"
//#include "pkcs7.h"
//#include "ctr_randomaccess.h"
//#include "ctr_bit_flip.h"
//#include "cbc_bit_flip.h"
//#include "profile.h"
//#include "cbc_bit_flip.h"
//#include "cbc_padding.h"
//#include "mac.h"
//#include "mac_attack.h"
//#include "sha1.h"
//#include "md4.h"
#include <curl/curl.h>
#include "timing.h"

using namespace std;

//void vectorTest();
//void fox();
//void challenge10();

int main(int argc, char** argv)
{
	curl_global_init(CURL_GLOBAL_DEFAULT);
	unsigned char* result = NULL;
	unsigned int resultLen = 0;

	timingAttack31((unsigned char*) "http://localhost:3001/?file=passwd&signature=", &result, &resultLen);

	for (unsigned int i; i < resultLen; i++)
		cout << result[i];
	cout << endl;

	delete [] result;
	curl_global_cleanup();

	/*
		const unsigned char orig[] = "The quick brown fox jumps over the lazy dog";
		const unsigned int origLen = strlen((char*) orig);
		unsigned char* hmac = NULL;
		unsigned int hmacLen = 0;

		generateSHA1HMac(orig, origLen, &hmac, &hmacLen);

		for (unsigned int i = 0; i < hmacLen; i++)
			cout << hmac[i];

		delete [] hmac;
	 */
	/*
	const unsigned char orig[] = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
	const unsigned int origLen = strlen((char*) orig);
	const unsigned char attackSuffix[] = ";admin=true";
	const unsigned int attackSuffixLen = strlen((char*) attackSuffix);
	unsigned char* attackMessage = NULL;
	unsigned int attackMessageLen = 0;
	unsigned char* attackMac = NULL;
	unsigned char* origHash = NULL;
	unsigned char* hex = NULL;
	unsigned int hexLen = 0;
	unsigned int origHashLen = 0;

	generateSHA1Mac(orig, origLen, &origHash, &origHashLen);

	sha1_mac_attack(orig, origLen, attackSuffix, attackSuffixLen, origHash, &attackMessage, &attackMessageLen, &attackMac);

	to_hex(attackMessage, &hex, attackMessageLen, &hexLen);
	cout << "Message: " << endl;
	for (unsigned int i = 0; i < hexLen; i++)
		cout << hex[i];
	cout << endl;

	delete [] hex;

	to_hex(attackMac, &hex, SHA1_LENGTH, &hexLen);
	cout << "MAC: " << endl;
	for (unsigned int i = 0; i < hexLen; i++)
		cout << hex[i];
	cout << endl;

	delete [] origHash;
	delete [] attackMessage;
	delete [] attackMac;
	delete [] hex;
	 */
	/*
	unsigned char message[] = "The quick brown fox jumps over the lazy dog";
	unsigned char* mac = NULL;
	unsigned int macLen = 0;
	
	generateMac(message, strlen((char*)message), &mac, &macLen);

	if (verifyMac(message, strlen((char*)message), mac, macLen))
		cout << "MAC checks out" << endl;
	else
		cout << "MAC verification error" << endl;
	
	delete [] mac;
	 */
	//	unsigned char* input = (unsigned char*)"AAAAAAAAAAAAAAAA";
	//	unsigned char* hash = NULL;

	//	sha1(input, 16, &hash);

	//	cout << sha1_mac_verify(NULL, 0, input, 16, hash) << endl;

	//	delete [] hash;

	/*	unsigned char* ct = NULL;
		unsigned int ctLen = 0;
		unsigned char* input = (unsigned char*) "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
		unsigned int inputLen = 3 * 16;
		unsigned char* buff = new unsigned char[3 * 16];
		unsigned char* plain = new unsigned char[3 * 16];
	
		c16_encrypt(input, &ct, inputLen, &ctLen);

		memcpy(buff, ct, 16);
		memset(buff + 16, 0, 16);
		memcpy(buff + 32, ct, 16);

		c27_decrypt(buff, 3 * 16, plain);

		for (unsigned int i = 0; i < 16; i++)
			cout << (unsigned char)(plain[i] ^ plain[i + (2 * 16)]);

		delete [] ct;
		delete [] buff;
		delete [] plain;
	 */
	/*	unsigned char* ct = NULL;
		unsigned int ctLen = 0;
		unsigned char input[] = "\0admin\0true\0";

		c26_encrypt(input, &ct, 12, &ctLen);

		ct[32] ^= ';';
		ct[38] ^= '=';
		ct[43] ^= ';';

		if (c26_checkForAdmin(ct, ctLen))
		{
			cout << "Admin found" << endl;
		}
		else
		{
			cout << "Admin not found" << endl;
		}

		delete [] ct;
	 */
	/*	unsigned char* ct = NULL;
		unsigned int ctLen = 0;
		unsigned char* plain = NULL;
	
		ctrRANDRWEncryptFromFile("/home/ramo/code/cryptopals/20.txt", &ct, &ctLen);
	
		ctrRANDRWAttack(ct, ctLen, &plain);
	
		for (unsigned int i = 0; i < ctLen; i++)
			cout << plain[i];
	
		ctrRANDRWDestroy();
		delete [] ct;
		delete [] plain;
	 */
	/*	unsigned char** cts = NULL;
		unsigned int* ctLens = NULL;
		unsigned int ctCount = 0;
	
		ctr20_encryptFromFile("/home/ramo/code/cryptopals/20.txt", &cts, &ctLens, &ctCount);
	
		ctr20_attack((const unsigned char**)cts, ctLens, ctCount);
	
		for (unsigned int i = 0; i < ctCount; i++)
		{
			delete [] cts[i];
		}
		delete [] cts;
		delete [] ctLens;
	 */
	/*
		const unsigned char input[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
		const unsigned int inputLen = strlen((char*)input);
		unsigned char* ct = NULL;
		unsigned int ctLen = 0;

		c24(input, inputLen, &ct, &ctLen);

		cout << attack_c24(ct, ctLen, input, inputLen) << endl;

		delete [] ct;
	 */
	/*	const unsigned char* input = (unsigned char*)"The quick brown fox jumps over the lazy dog";
		unsigned int inputLen = strlen((char*)input);
		unsigned char* ct = new unsigned char[inputLen];
		unsigned char* pt = new unsigned char[inputLen];
		short key = 8512;

		mtEncrypt(input, inputLen, ct, key);
		mtDecrypt(ct, inputLen, pt, key);

		for (unsigned int i = 0; i < inputLen; i++)
			cout << pt[i];

		delete [] ct;
		delete [] pt;
	 */
	/*	mt19937 source, dest;
		source.seed();
		for (unsigned int i = 0; i < 20105; i++)
			source.getRand32();

		cloneMT(&source, &dest);
        
		for (unsigned int i = 0; i < 100000; i++)
			if (source.getRand32() != dest.getRand32())
				cout << "Mismatch" << endl;
	 */
	/*      unsigned int foo = mtGenerateFromUnknownTimestamp();
		cout << discoverSeed(foo) << endl;
	 */
	/*	ctr_performEncryptions();
	ctr_attack();
	ctr_destroy();
	 */

	/*
		const unsigned char input[] = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
		unsigned char* inputRaw = NULL;
		unsigned int inputRawLen = 0;
		unsigned char* plain = NULL;
		unsigned char nonce[] = {0,0,0,0,0,0,0,0};

		from_base64(input, &inputRaw, strlen((char*)input), &inputRawLen);

		plain = new unsigned char[inputRawLen];

		aesDecryptCTR(inputRaw, plain, (unsigned char*)"YELLOW SUBMARINE", nonce, inputRawLen, 16);

		for (unsigned int i = 0; i < inputRawLen; i++)
			cout << plain[i];

		delete [] inputRaw;
		delete [] plain;
	 */
	/*	unsigned char* ct = NULL;
		unsigned int ctLen = 0;
		unsigned char* iv = NULL;
		unsigned int ivLen = 0;
		unsigned char* plain = NULL;
		unsigned int plainLen = 0;
		unsigned char* unpadded = NULL;
		unsigned int unpaddedLen = 0;

		c17_encrypt(&ct, &iv, &ctLen, &ivLen);

		c17_attack(ct, ctLen, &plain, &plainLen, iv, 16);

		removePCKSPad(plain, &unpadded, plainLen, &unpaddedLen, 16);

		for (unsigned int i = 0; i < unpaddedLen; i++)
			cout << unpadded[i];

		delete [] plain;
		delete [] iv;
		delete [] ct;
		delete [] unpadded;
	 */
	/*	unsigned char* ct = NULL;
		unsigned int ctLen = 0;
		unsigned char input[] = "AadminAtrueA";

		c16_encrypt(input, &ct, strlen((char*)input), &ctLen);
		ct[32 - 16] ^= ('A' ^ ';');
		ct[38 - 16] ^= ('A' ^ '=');
		ct[43 - 16] ^= ('A' ^ ';');

		if (c16_checkForAdmin(ct, ctLen))
		{
			cout << "Admin found" << endl;
		} else {
			cout << "Admin not found" << endl;
		}

		delete [] ct;
	 */
	/*	unsigned int blockSize = getBlockSize(c14_encryptOracle);
		unsigned char* result = NULL;
		unsigned int resultLen = 0;

		if (!isECBMode(blockSize, c14_encryptOracle))
		{
			cout << "NOT ECB MODE!" << endl;
			return 0;
		}

		getUnknownString(blockSize, &result, &resultLen, c14_encryptOracle);
	
		for (unsigned int i = 0; i < resultLen; i++)
		{
			cout << result[i];
		}
		delete [] result;
	 */
	/*	//1234567890123456|7890123456789012|3456789012345678|9012345678901234
		//email=foo@bar.co|m&uid=10&role=us|er
		//email=foo@bar.co|mmm&uid=10&role=|user
		//email=foo@bar.co|admin(\11's)    |&uid=10&role=use|r

		const char* email1 = "foo@bar.commm"; // will push 'user' into start of block 3
		const char* email2 = "foo@bar.coadmin\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B"; // places 'admin' and pkcs padding into block 2

		unsigned char* enc1 = NULL;
		unsigned char* enc2 = NULL;
		unsigned int enc1Len = 0;
		unsigned int enc2Len = 2;

		profile p;

		p.profileFor(email1, 14);
		p.encrypt(&enc1, &enc1Len);
		p.profileFor(email2, 26);
		p.encrypt(&enc2, &enc2Len);
		memcpy(enc1 + 32, enc2 + 16, 16);
		p.decrypt(enc1, enc1Len);
		cout << p.toString() << endl;

		delete [] enc2;
		delete [] enc1;
	 */
	/*	unsigned int blockSize = getBlockSize();
		unsigned char* result = NULL;
		unsigned int resultLen = 0;

		if (!isECBMode(blockSize))
		{
			cout << "NOT ECB MODE!" << endl;
			return 0;
		}
		getUnknownString(blockSize, &result, &resultLen);
		for (unsigned int i = 0; i < resultLen; i++)
		{
			cout << result[i];
		}
		delete [] result;
	 */
	/*	const unsigned char source[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
		unsigned char* dest = NULL;
		unsigned int destLen = 0;

		challenge11(source, &dest, strlen((char*)source), &destLen);


		cout << countZeroHammings(dest, destLen, 16) << endl;


		delete [] dest;
	 */
	//	vectorTest();
	//	fox();
	//	challenge10();

	/*const unsigned char key[] = "YELLOW SUBMARINE";
	unsigned char* cipherb64 = NULL;
	unsigned char* cipherRaw = NULL;
	unsigned char* plaintext = NULL;
	unsigned int cipherb64Len = 0;
	unsigned int cipherRawLen = 0;
	unsigned int plaintextLen = 0;

	readFromFile("1-7.txt", &cipherb64, &cipherb64Len);
	from_base64(cipherb64, &cipherRaw, cipherb64Len, &cipherRawLen);

	// plaintext is at most as big as the ciphertext
	plaintext = new unsigned char[cipherRawLen];

	aesDecryptECB(cipherRaw, plaintext, key, cipherRawLen, 16);

	cout << plaintext << endl;


	delete [] cipherb64;
	delete [] cipherRaw;
	delete [] plaintext;
	 */
	/*	ifstream fin("1-8.txt");
		string cipherHex = "";
		unsigned char* cipherRaw = NULL;
		unsigned int cipherRawLen = 0;

		while (!fin.eof())
		{
			fin >> cipherHex;
			from_hex((unsigned char*)cipherHex.c_str(), &cipherRaw, cipherHex.length(), &cipherRawLen);
			if (countZeroHammings(cipherRaw, cipherRawLen, 16))
			{
				cout << cipherHex << endl;
			}
			delete [] cipherRaw;
		}
	 */
	/*	ifstream fin("1-6.txt");
		string cipherb64 = "";
		unsigned char* cipherRaw = NULL;
		unsigned int cipherRawLen = 0;

		while (!fin.eof())
		{
			string s;
			fin >> s;
			cipherb64 += s;
		}
		from_base64((unsigned char*)cipherb64.c_str(), &cipherRaw, cipherb64.length(), &cipherRawLen);

		unsigned int keyLength = findRepeatingXORKeyLength(cipherRaw, cipherRawLen, 80);

		cout << "keyLength: " << keyLength << endl;

		unsigned char* key = new unsigned char[keyLength + 1];
		unsigned char** cipherblocks = new unsigned char*[keyLength];
		for (unsigned int i = 0; i < keyLength; i++)
		{
			cipherblocks[i] = new unsigned char[cipherRawLen / keyLength + 1];
			memset(cipherblocks[i], 0, cipherRawLen / keyLength + 1);
		}
		for (unsigned int i = 0; i < cipherRawLen; i++)
		{
			cipherblocks[i % keyLength][i / keyLength] = cipherRaw[i];
		}

		for (unsigned int i = 0; i < keyLength; i++)
		{
			key[i] = findRepeatingXORKey(cipherblocks[i], cipherRawLen / keyLength + 1);
		}

		cout << "Suspected key: ";
		for (unsigned int i = 0; i < keyLength; i++) cout << key[i];
		cout << endl;

		cout << "Enter key to try: ";
		cin.getline((char*)key, keyLength + 1, '\n');

		unsigned char* keyBuff = new unsigned char[cipherRawLen];
		unsigned char* plain = NULL;
		fillBufferRepeating(key, keyLength, keyBuff, cipherRawLen);
		xorBuffer(keyBuff, cipherRaw, &plain, cipherRawLen);

		for (unsigned int i = 0; i < cipherRawLen; i++) cout << plain[i];
		cout << endl;

		for (unsigned int i = 0; i < keyLength; i++)
		{
			delete [] cipherblocks[i];
		}
		delete [] keyBuff;
		delete [] cipherblocks;
		delete [] cipherRaw;
		delete [] key;
		delete [] plain;

	 */
	/*	const unsigned char key[] = "ICE";
		unsigned char keyBuff[128] = {};
		const unsigned char plain1[] = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
		unsigned char* cipher1raw = NULL;
		unsigned char* cipher1hex = NULL;
		unsigned int cipher1hexLen = 0;

		fillBufferRepeating(key, strlen((char*)key), keyBuff, 128);

		xorBuffer(plain1, keyBuff, &cipher1raw, strlen((char*)plain1));

		to_hex(cipher1raw, &cipher1hex, strlen((char*)plain1), &cipher1hexLen);

		cout << cipher1hex << endl;

		delete [] cipher1raw;
		delete [] cipher1hex;
	 */
	/*	ifstream fin("1-4.txt");
		unsigned char ciphertextHex[128] = {};

		while (!fin.eof())
		{
			fin >> ciphertextHex;
			const unsigned int ciphertextHexLen = strlen((char*)ciphertextHex);
			unsigned char* ciphertextRaw = NULL;
			unsigned int ciphertextRawLen = 0;
			char foo = 0;

			from_hex(ciphertextHex, &ciphertextRaw, ciphertextHexLen, &ciphertextRawLen);

			foo = findRepeatingXORKey(ciphertextRaw, ciphertextRawLen);

			unsigned char* keybuff = new unsigned char[ciphertextRawLen];
			unsigned char* plaintext = NULL;
			memset(keybuff, (unsigned char)foo, ciphertextRawLen);
			xorBuffer(keybuff, ciphertextRaw, &plaintext, ciphertextRawLen);

			float score = scoreBuffer(plaintext, ciphertextRawLen);
			if (score < 10)
			{
				cout << score << " " << plaintext << endl;
			}	
			delete [] keybuff;
			delete [] plaintext;
			delete [] ciphertextRaw;
		}

	 */
	/*
		const unsigned char ciphertextHex[] = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
		const unsigned int ciphertextHexLen = strlen((char*)ciphertextHex);
		unsigned char* ciphertextRaw = NULL;
		unsigned int ciphertextRawLen = 0;

		from_hex(ciphertextHex, &ciphertextRaw, ciphertextHexLen, &ciphertextRawLen);

		unsigned char key = findRepeatingXORKey(ciphertextRaw, ciphertextRawLen);

		unsigned char* keybuff = new unsigned char[ciphertextRawLen];
		unsigned char* plaintext = NULL;
		memset(keybuff, (unsigned char)key, ciphertextRawLen);
		xorBuffer(keybuff, ciphertextRaw, &plaintext, ciphertextRawLen);
	
		cout << "Key: " << key << endl;
		cout << plaintext << endl;

		delete [] plaintext;
		delete [] ciphertextRaw;
		delete [] keybuff;
	 */
	/*
		unsigned char* keybuff = new unsigned char[ciphertextRawLen];
		unsigned char* plaintext = NULL;
		memset(keybuff, (unsigned char)foo, ciphertextRawLen);
		xorBuffer(keybuff, ciphertextRaw, &plaintext, ciphertextRawLen);

		cout << best << " " << plaintext << endl;

		delete [] keybuff;
		delete [] plaintext;
		delete [] ciphertextRaw;
	 */
	/*	const unsigned char input[] = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
		unsigned char* raw = NULL;
		unsigned char* hex = NULL;
		unsigned int rawLen = 0;
		unsigned int hexLen = 0;

		from_base64(input, &raw, strlen((const char*)input), &rawLen);
		to_hex(raw, &hex, rawLen, &hexLen);

		cout << hex << endl;

		delete [] raw;
		delete [] hex;
	 */
	/*
		const unsigned char foo[] = "1c0111001f010100061a024b53535009181c";
		unsigned char* fooraw = NULL;
		unsigned int foorawlen = 0;
		const unsigned char bar[] = "686974207468652062756c6c277320657965";
		unsigned char* barraw = NULL;
		unsigned int barrawlen = 0;

		unsigned char* destraw = NULL;

		from_hex(foo, &fooraw, strlen((char*)foo), &foorawlen);
		from_hex(bar, &barraw, strlen((char*)bar), &barrawlen);

		xorBuffer(fooraw, barraw, &destraw, foorawlen);

		unsigned char* destHex = NULL;
		unsigned int destHexLen = 0;

		to_hex(destraw, &destHex, foorawlen, &destHexLen);


		cout << destHex << endl;

		delete [] fooraw;
		delete [] barraw;
		delete [] destraw;
		delete [] destHex;
	 */
	return 0;
}
/*
void vectorTest()
{
	const unsigned char key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
	const unsigned char iv[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
//	const unsigned char plaintext[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
//					0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
//					0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
//					0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};
//	unsigned char ciphertext[64] = {0};

	const unsigned char ciphertext[] = {0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
					0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
					0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
					0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7};
	unsigned char plaintext[64] = {0};

//	aesEncryptCBC(plaintext, ciphertext, key, iv, 64, 16);
	aesDecryptCBC(ciphertext, plaintext, key, iv, 64, 16);

	cout << "final:   ";
	for (unsigned int i = 0; i < 64; i++)
	{
		cout << setw(2) << setfill('0') << hex << (int)plaintext[i];
	}
	cout << endl;

	cout << "correct: 6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710" << endl;
}

void fox()
{
	const unsigned char key[] = "YELLOW SUBMARINE";
	const unsigned char iv[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	const unsigned char orig[] = "The quick brown fox jumps over the lazy dog";
	unsigned char* origPadded = NULL;
	unsigned char ct[48] = {0};
	unsigned char pt[48] = {0};

	try {
		addPKCS7Pad(orig, &origPadded, strlen((char*)orig), 48);
		aesEncryptCBC(origPadded, ct, key, iv, 48, 16);
		aesDecryptCBC(ct, pt, key, iv, 48, 16);
		cout << "original: " << orig << endl;
		cout << "decrypt:  ";
		for (unsigned int i = 0; i < 48; i++)
		{
			cout << pt[i];
		}
		cout << endl;
	} catch (PKCS7Exception e) {
		cout << e.getReason() << endl;
	}

	delete [] origPadded;
}

void challenge10()
{
	const unsigned char key[] = "YELLOW SUBMARINE";
	const unsigned char iv[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	unsigned char* cipherb64 = NULL;
	unsigned char* cipherRaw = NULL;
	unsigned char* plaintext = NULL;
	unsigned int cipherb64Len = 0;
	unsigned int cipherRawLen = 0;
//	unsigned int plaintextLen = 0;

	readFromFile("2-10.txt", &cipherb64, &cipherb64Len);
	from_base64(cipherb64, &cipherRaw, cipherb64Len, &cipherRawLen);

	// plaintext is at most as big as the ciphertext
	plaintext = new unsigned char[cipherRawLen];

	aesDecryptCBC(cipherRaw, plaintext, key, iv, cipherRawLen, 16);

	cout << plaintext << endl;

	delete [] cipherb64;
	delete [] cipherRaw;
	delete [] plaintext;
}
 */