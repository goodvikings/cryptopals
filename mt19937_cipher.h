#ifndef MT19937_CIPHER_H
#define MT19937_CIPHER_H

void mtEncrypt(const unsigned char* source, const unsigned int sourceLen, unsigned char* dest, unsigned int key);
void mtDecrypt(const unsigned char* source, const unsigned int sourceLen, unsigned char* dest, unsigned int key);

void c24(const unsigned char* source, const unsigned int sourceLen, unsigned char** dest, unsigned int* destLen);
unsigned int attack_c24(const unsigned char* ct, const unsigned int ctLen, const unsigned char* searchText, const int searchtextLen);

#endif