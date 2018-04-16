#ifndef SHA1_MAC_H
#define SHA1_MAC_H

void generateMac(const unsigned char* message, const unsigned int messageLen, unsigned char** result, unsigned int* resultLen);
bool verifyMac(const unsigned char* message, const unsigned int messageLen, const unsigned char* hash, const unsigned int hashLen);

#endif