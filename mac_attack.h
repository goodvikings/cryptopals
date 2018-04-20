#ifndef SHA1_MAC_ATTACK
#define SHA1_MAC_ATTACK

void sha1_mac_attack(const unsigned char* origMessage, const unsigned int origMessageLen, const unsigned char* toAppend, const unsigned int toAppendLen, const unsigned char* origMac, unsigned char** resultMessage, unsigned int* resultMessageLen, unsigned char** resultMac);
void md4_mac_attack(const unsigned char* origMessage, const unsigned int origMessageLen, const unsigned char* toAppend, const unsigned int toAppendLen, const unsigned char* origMac, unsigned char** resultMessage, unsigned int* resultMessageLen, unsigned char** resultMac);

#endif