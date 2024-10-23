#ifndef ELGAMMAL
#define ELGAMMAL

#include <bits/stdc++.h>
#include <pbc.h>
#include <gmp.h>
#include "cryptopp/cryptlib.h"
#include "cryptopp/rijndael.h"
#include "cryptopp/modes.h"
#include "cryptopp/files.h"
#include "cryptopp/osrng.h"
#include "cryptopp/hex.h"
#include "cryptopp/aes.h"
#include "cryptopp/filters.h"
#include "cryptopp/gcm.h"
#include"cryptopp/rdrand.h"
#include "PS_Commit.h"

using namespace CryptoPP;
using byte = unsigned char;
class ElGammal{
    public:
        element_s g;
        params pp; 
        ElGammal();
        void KeyGen(element_s *sk, element_s *pk);
        void Encrypt(byte msg[],element_s *pk,std::pair<element_s, byte*> *enc);
        void Decrypt(element_s *sk,std::pair<element_s, byte*> *enc, byte* msg);
};
#endif