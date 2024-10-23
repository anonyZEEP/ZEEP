#ifndef SYMMETRIC
#define SYMMETRIC
// #define SIZE_OF_ZR 32
// #define SIZE_OF_G1 32
// #define SIZE_OF_G2 
#include <bits/stdc++.h>
#include "cryptopp/osrng.h"
#include <string>
#include <cstdlib>
#include "cryptopp/cryptlib.h"
#include "cryptopp/hex.h"
#include "cryptopp/filters.h"
#include "cryptopp/aes.h"
#include "cryptopp/ccm.h"
#include "assert.h"

using namespace CryptoPP;
using byte = unsigned char;

class Symmetric_enc {
    public:
        Symmetric_enc();
        std::pair<byte *, byte*> KeyGen(int key_length, int block_size);
        std::pair<byte*, size_t> Encrypt_payload(byte* key, byte* iv, std::string msg);
        std::pair<byte*, size_t> Decrypt_payload(byte* key, byte* iv, std::string cipher);
        

    private:
    
};

#endif