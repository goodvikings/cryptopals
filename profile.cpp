#include <string>
#include "aes.h"
#include "pkcs7.h"
#include "profile.h"

static const unsigned char key[16] = {147, 84, 114, 40, 202, 22, 198, 227, 218, 96, 199, 176, 201, 157, 189, 39};

profile::profile()
{
}

profile::profile(const char* encoded, const unsigned int encodedLen)
{
	this->fromEncoded(encoded, encodedLen);
}

void profile::fromEncoded(const char* encoded, const unsigned int encodedLen)
{
	unsigned int pairStart = 0;
	unsigned int pairEnd = 0;
	unsigned int pairSeperator = 0;

	while (pairStart < encodedLen)
	{
		for (pairEnd = pairStart; pairEnd < encodedLen && encoded[pairEnd] != '&'; pairEnd++);
		for (pairSeperator = pairStart; pairSeperator < encodedLen && encoded[pairSeperator] != '='; pairSeperator++);
		this->pairs.push_back(kvpair(string(&(encoded[pairStart]), pairSeperator - pairStart), string(&(encoded[pairSeperator + 1]), pairEnd - pairSeperator -1)));
		pairStart = pairEnd + 1;
	}
}

void profile::profileFor(const char* email, const unsigned int emailLen)
{
	this->pairs.clear();
	string emailLocal = email;
	int pos = 0;
	while ((pos = emailLocal.find("&")) != (int)std::string::npos)
		emailLocal.replace(pos, 1, "%26");
	while ((pos = emailLocal.find("=")) != (int)std::string::npos)
		emailLocal.replace(pos, 1, "%3D");

	this->pairs.push_back(kvpair(string("email"), emailLocal));
	this->pairs.push_back(kvpair("uid", "10"));
	this->pairs.push_back(kvpair("role", "user"));
}

const string profile::toEncodedString()
{
	string retVal;
	for (vector<kvpair>::iterator i = this->pairs.begin(); i != this->pairs.end(); i++)
	{
		retVal += i->key;
		retVal += "=";
		retVal += i->value;
		if (i != this->pairs.end() - 1)
			retVal += '&';
	}
	return retVal;
}

const string profile::toString()
{
	string retVal = "{\n";
	for (vector<kvpair>::iterator i = this->pairs.begin(); i != this->pairs.end(); i++)
	{
		retVal += "\t";
		retVal += i->key;
		retVal += ": '";
		retVal += i->value;
		retVal += "'";
		if (i != this->pairs.end() - 1)
			retVal += ',';
		retVal += '\n';
	}
	retVal += '}';
	return retVal;
}

const void profile::encrypt(unsigned char** dest, unsigned int* destLen)
{
	string source = this->toEncodedString();
	unsigned char* padded = NULL;
	*destLen = ((source.length() / 16) + 1) * 16;
	*dest = new unsigned char[*destLen];

	addPKCS7Pad((unsigned char*)source.c_str(), &padded, source.length(), *destLen);
	aesEncryptECB(padded, *dest, key, *destLen, 16);

	delete [] padded;
}

void profile::decrypt(const unsigned char* source, const unsigned int sourceLen)
{
	this->pairs.clear();

	unsigned char* decrypted = new unsigned char[sourceLen];
	unsigned char* unpadded = NULL;
	unsigned int unpaddedLen = 0;

	aesDecryptECB(source, decrypted, key, sourceLen, 16);
	removePCKSPad(decrypted, &unpadded, sourceLen, &unpaddedLen, 16);

	this->fromEncoded((char*)unpadded, unpaddedLen);

	delete [] decrypted;
	delete [] unpadded;
}
