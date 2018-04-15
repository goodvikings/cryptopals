#ifndef MISC_H
#define MISC_H

void xorBuffer(const unsigned char* foo, const unsigned char* bar, unsigned char** dest, const unsigned int len);
void fillBufferRepeating(const unsigned char* source, const unsigned int sourceLen, unsigned char* dest, const unsigned int destLen);
unsigned char findRepeatingXORKey(const unsigned char* ciphertext, const unsigned int len);
unsigned int findRepeatingXORKeyLength(const unsigned char* source, const unsigned int len, const unsigned char max);

#endif