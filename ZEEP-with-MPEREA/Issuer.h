#ifndef ISSUER
#define ISSUER

#include "PS_Commit.h"
#include "Accumulator.h"
#include "DGSA.h"

class Issuer {
public:
    std::vector<element_s*> pk_c;    // public key for signing commitment
    element_s* pk_acc;               // public key of accumulator 
                  
    std::vector<element_s*> psign_pk; // public key for dgsa token
    element_s* acc_val;
    int K;
    std::vector<std::tuple<element_s*, element_s*, element_s*>> wl;
    std::vector<element_s*> bl;
    element_s* epoch;
    element_s* t_cap;
    params p;
    PSCommit pscom;
    Accumulator acc;
    std::tuple<element_s*, element_s*, element_s*, element_s*> proof_params;


    Issuer();  // Constructor declaration

    void Setup(int revoc_window, int bl_size);
    std::tuple<std::pair<element_s*, element_s*>, std::pair<element_s*, element_s*>> 
    Register_User(std::pair<element_s*, std::tuple<element_s*, element_s*, element_s*>> req);

    std::tuple<std::pair<element_s*, element_s*>, std::pair<element_s*, element_s*>, std::vector<element_s*>> 
    Autheticate_User(std::tuple<std::tuple<element_s*,element_s*, element_s*,std::vector<element_s*>>, element_s*,element_s*, element_s*,element_s*,element_s*, std::vector<ZKP*>> tok);



private:
    element_s* sk_acc; 
    bool Verify_pi_reg(element_s* comm, std::tuple<element_s*, element_s*, element_s*> *tok);
    std::pair<unsigned char*, int> convert_to_byte(element_s* c, element_s* g, element_s* Y3);
    element_s* sk_c;
    std::pair<unsigned char*, int> convert_to_byte(element_s* u, element_s* p1, element_s* p2, element_s* sig1, element_s* sig2, element_s* c1, element_s* c2);

    
    std::vector<element_s*> psign_sk;
    DGSA dg;
    
};

#endif
