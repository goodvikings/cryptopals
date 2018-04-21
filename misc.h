#ifndef MISC_H
#define MISC_H

void readFromFile(const char* filename, unsigned char** dest, unsigned int* destLen);
bool searchForText(const unsigned char* haystack, const unsigned int haystacklen, const unsigned char* needle, const unsigned int needleLen);
void encode(const unsigned char* source, const unsigned int sourceLen, unsigned char** dest, unsigned int* destLen);
int curl(const unsigned char* url);

#endif