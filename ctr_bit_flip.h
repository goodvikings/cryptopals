#ifndef CBC_BIT_FLIP_H
#define CBC_BIT_FLIP_H

void c26_encrypt(const unsigned char* source, unsigned char** dest, const unsigned int sourceLen, unsigned int* destLen);
bool c26_checkForAdmin(const unsigned char* source, const unsigned int sourceLen);

#endif