#ifndef CTR_H
#define CTR_H

#include <vector>
using namespace std;

void ctr19_performEncryptions();
void ctr19_destroy();
void ctr19_attack();

void ctr20_encryptFromFile(const char* filename, unsigned char*** cts, unsigned int** ctLens, unsigned int* ctCount);
void ctr20_attack(const unsigned char** cts, const unsigned int* ctLens, const unsigned int ctCount);

#endif