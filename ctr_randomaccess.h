#ifndef CTR_RANDOMACCESS_H
#define CTR_RANDOMACCESS_H

void ctrRANDRWEncryptFromFile(const char* filename, unsigned char** dest, unsigned int* destLen);
void ctrRANDRWEdit(unsigned char* ct, const unsigned int ctLen, unsigned int offset, const unsigned char* newPlain, const unsigned int newPlainLen);
void ctrRANDRWAttack(const unsigned char* ct, const unsigned int ctLen, unsigned char** plain);
void ctrRANDRWDestroy();

#endif