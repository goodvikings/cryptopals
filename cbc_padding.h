#ifndef CBC_PADDING_H
#define CBC_PADDING_H

void c17_encrypt(unsigned char** dest, unsigned char** iv, unsigned int* destLen, unsigned int* ivLen);
bool c17_decryptAndCheckPadding(const unsigned char* source, const unsigned int sourceLen, const unsigned char* iv, const unsigned int ivLen);
void c17_attack(const unsigned char* source, const unsigned int sourceLen, unsigned char** dest, unsigned int* destLen, const unsigned char* iv, const unsigned int blocksize);

#endif