#ifndef DGSAA
#define DGSAA

#include <bits/stdc++.h>
#include <pbc.h>
#include <gmp.h>
#include "PS_Commit.h"
#include "PS_Sign.h"
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

using namespace CryptoPP;
using byte = unsigned char;

class DGSA{
    public:

        DGSA();
        void Setup(params pp, std::vector<element_s*> *ps_vk, std::vector<element_s*> *ps_sk);

        void Issuer_DGSA(params p, std::vector<element_s*> *sk,std::vector<std::tuple<element_s*, element_s*, element_s*> > *st, 
                         element_s* id, element_s* epoch, std::vector<element_s*> *sign);
        void Vehicle_DGSA(params p, element_s id, element_s epoch, std::vector<element_s*> *vk, std::vector<element_s*> *sign,
                         std::tuple<element_s, element_s , element_s, element_s, element_s> *cred);
        void Auth(std::vector<element_s*> *vk,std::tuple<element_s, element_s , element_s, element_s, element_s> *cred,
                 std::tuple<element_s, element_s, std::pair<element_s, byte*> > *msg, 
                 std::tuple< element_s, element_s, element_s, element_s, element_s> *tok, params p);
        
        bool Verify(std::vector<element_s*> *vk, std::tuple<element_s, element_s, std::pair<element_s, byte*> > *msg, element_s epoch, 
                    std::tuple< element_s, element_s, element_s, element_s, element_s> *tok, params p);
        void Open();
    
    
        PS_Sign ps;
        
        // std::vector<element_s*> ps_vk;
        // std::vector<element_s*> ps_sk;
    private:
        
        std::pair<byte*, int> convert_to_byte( element_s* u, element_s* epoch, element_s* msg1,element_s* msg2,byte* msg3,element_s* sig1, 
                element_s* sig2, std::vector<element_s*> *vk);
        void print_text(byte text[],int size);
};
#endif