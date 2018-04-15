#ifndef ECB_H
#define ECB_H

void c12_encryptOracle(const unsigned char* source, unsigned char** dest, const unsigned int sourceLen, unsigned int* destLen);
void c14_encryptOracle(const unsigned char* source, unsigned char** dest, const unsigned int sourceLen, unsigned int* destLen);
void getUnknownString(const unsigned int blocksize, unsigned char** out, unsigned int* outLen, void (*oracle)(const unsigned char*, unsigned char**, const unsigned int, unsigned int*));
unsigned int getBlockSize(void (*oracle)(const unsigned char*, unsigned char**, const unsigned int, unsigned int*));
bool isECBMode(const unsigned int blocksize, void (*oracle)(const unsigned char*, unsigned char**, const unsigned int, unsigned int*));

#endif
