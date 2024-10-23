#ifndef ACCUMULATOR
#define ACCUMULATOR

#include <bits/stdc++.h>
#include <pbc.h>
#include <gmp.h>
#include "PS_Commit.h"
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
// struct params
// {
//         element_s p;
//         element_s G;
//         element_s G_bar;
//         element_s G_T;
//         pairing_s e;
// };

class ZKP{
    public:
    element_s* A2;
    element_s* B1;
    element_s* B2;
    element_s* CI;
    element_s* challenge;
    element_s* sr;
    element_s* st1;
    element_s* st3;
    element_s* st4;
    element_s* sd3;
    element_s* sd4;
    
    ZKP(element_s* A2, element_s* B1, element_s* B2, element_s* CI, element_s* challenge, element_s* sr, element_s* st1,element_s* st3,element_s* st4,element_s* sd3,element_s* sd4, params pp){
        
        this->A2 = (element_s*) malloc(sizeof(*A2));
        this->B1 = (element_s*) malloc(sizeof(*B1));
        this->B2 = (element_s*) malloc(sizeof(*B2));
        this->CI = (element_s*) malloc(sizeof(*CI));
        this->challenge = (element_s*) malloc(sizeof(*challenge));
        this->sr = (element_s*) malloc(sizeof(*sr));
        this->st1 = (element_s*) malloc(sizeof(*st1));
        this->st3 = (element_s*) malloc(sizeof(*st3));
        this->st4 = (element_s*) malloc(sizeof(*st4));
        this->sd3 = (element_s*) malloc(sizeof(*sd3));
        this->sd4 = (element_s*) malloc(sizeof(*sd4));

        
        element_init_G2(this->A2, pp.e);
        element_init_G1(this->B1, pp.e);
        element_init_G1(this->B2, pp.e);
        element_init_G2(this->CI, pp.e);
        element_init_Zr(this->challenge, pp.e);
        element_init_Zr(this->sr, pp.e);
        element_init_Zr(this->st1, pp.e);
        element_init_Zr(this->st3, pp.e);
        element_init_Zr(this->st4, pp.e);
        element_init_Zr(this->sd3, pp.e);
        element_init_Zr(this->sd4, pp.e);
        element_printf("A2 = %B\n", A2);
        element_set(this->A2, A2);
        element_set(this->B1, B1);
        element_set(this->B2, B2);
        element_set(this->CI, CI);
        element_set(this->challenge, challenge);
        element_set(this->sr, sr);
        element_set(this->st1, st1);
        element_set(this->st3, st3);
        element_set(this->st4, st4);
        element_set(this->sd3, sd3);
        element_set(this->sd4, sd4);
    }
    ~ZKP(){
        delete A2;
        delete B1;
        delete B2;
        delete challenge;
        delete CI;
        delete sr;
        delete st1;
        delete st3;
        delete st4;
        delete sd3;
        delete sd4;
        delete sr;
    }
    
};

class Accumulator {
public:
    
    Accumulator();  // Constructor declaration

    void Setup();
    void KeyGen(params pp, element_s *vk, element_s *sk);
    void Add(element_s* sk, params pp, element_s* x, element_s* delta);
    void Delete(element_s* sk, params pp, element_s* x, element_s* vk);
    void NonMemWithCreate(element_s* sk, params pp, element_s* x, std::vector<element_s* > *wl, std::pair<element_s*, element_s*> *witness);
    void NonMemWithUpOnAdd(element_s* x, std::pair<element_s*, element_s*> *witness, element_s* y, params pp, element_s* delta);
    void NonMemWithUpOnDelete(element_s* x, std::pair<element_s*, element_s*> *witness, element_s* y, params pp, element_s* delta);
    bool VerNonMem(params pp, element_s* x, std::pair<element_s*, element_s*> *witness, element_s* pub, element_s* delta);

    ZKP* ConstructZkpOfWitness(params pp, element_s* y, std::pair<element_s*, element_s*> *witness,element_s* delta, element_s* vk,
                              std::tuple<element_s*, element_s*, element_s*, element_s*> *proof_params);

    bool VerifyZKP(params pp,std::tuple<element_s*, element_s*, element_s*, element_s*, element_s*, element_s*, element_s*, element_s*, element_s*,element_s*, element_s*> *proof, 
                   std::tuple<element_s*, element_s*, element_s*, element_s*> *proof_params, element_s* delta);
    //void getWitness(element_s* x, element_s* prod, params p);
private:
    std::pair<unsigned char*, int> convert_to_byte( std::tuple<element_s*, element_s*, element_s*, element_s*> *proof, element_s* A2, element_s* B1,element_s* B2,element_s* CI,element_s* R21, element_s* R22, element_s* R3);
    
    void print_text(byte text[],int size);


};


#endif
