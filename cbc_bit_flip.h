#ifndef CTR_BIT_FLIP_H
#define CTR_BIT_FLIP_H

void c16_encrypt(const unsigned char* source, unsigned char** dest, const unsigned int sourceLen, unsigned int* destLen);
bool c16_checkForAdmin(const unsigned char* source, const unsigned int sourceLen);
bool c27_decrypt(const unsigned char* source, const unsigned int sourceLen, unsigned char* dest);

#endif