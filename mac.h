#ifndef SHA1_MAC_H
#define SHA1_MAC_H

void generateSHA1Mac(const unsigned char* message, const unsigned int messageLen, unsigned char** result, unsigned int* resultLen);
bool verifySHA1Mac(const unsigned char* message, const unsigned int messageLen, const unsigned char* hash, const unsigned int hashLen);
void generateMD4Mac(const unsigned char* message, const unsigned int messageLen, unsigned char** result, unsigned int* resultLen);
bool verifyMD4Mac(const unsigned char* message, const unsigned int messageLen, const unsigned char* hash, const unsigned int hashLen);

#endif