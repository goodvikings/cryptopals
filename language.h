#ifndef LANGUAGE_H
#define LANGUAGE_H

double scoreBuffer(const unsigned char* source, const unsigned int len);
unsigned int hammingDiffernece(const unsigned char* foo, const unsigned char* bar, const unsigned int len);
unsigned int countZeroHammings(const unsigned char* buff, const unsigned int len, const unsigned int blockLen);

#endif