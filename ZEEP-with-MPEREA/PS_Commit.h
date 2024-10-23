#ifndef PS_COMMIT
#define PS_COMMIT

// #define SIZE_OF_ZR 32
// #define SIZE_OF_G1 32
// #define SIZE_OF_G2 
#include <bits/stdc++.h>
#include <pbc.h>

struct params
{
        element_s *p;
        element_s *G;
        element_s *G_bar;
        element_s *G_T;
        pairing_s *e;
};

class PSCommit {
public:
    element_s urr;
    PSCommit();  // Constructor declaration

    params Setup();
    void KeyGen(int num_of_attri, params pp, element_s *sk, std::vector<element_s*> *vk);
    std::pair<element_s*, element_s*> GenCommitment(std::vector<element_s*> *msg, std::vector<element_s*> *public_key, params pp);
    std::pair<element_s*, element_s*> Sign(element_s* C, element_s* sk, element_s* epoch, std::vector<element_s*> *pub_key, params pp);
    void Unblind(std::pair<element_s*, element_s*> sig, element_s* r, params pp);
    bool Verify(std::pair<element_s*, element_s*> sig,std::vector<element_s*> msg, element_s* epoch, std::vector<element_s*> pub_key, params pp);

private:
    params pp;

    
};

#endif