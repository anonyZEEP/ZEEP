#ifndef DAEE
#define DAEE

#include <iostream>
#include <string>
#include "cryptopp/osrng.h"
#include "cryptopp/hex.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/filters.h"
#include "cryptopp/aes.h"
#include "cryptopp/gcm.h"

using namespace CryptoPP;
using byte = unsigned char;

class DAE {
    public:
        DAE();
        std::pair<byte *, byte*> KeyGen(int key_size, int block_size, int tag_size);
        std::pair<byte*, size_t> Encrypt(byte* key, byte* iv, std::string msg);
        std::pair<byte*, size_t> Decrypt(byte* key, byte* iv, std::string cipher);
        

    private:
        size_t KEY_LEN;
        size_t IV_LEN;
        size_t TAG_LEN;
    
};

#endif