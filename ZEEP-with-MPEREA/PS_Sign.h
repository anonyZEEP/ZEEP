
#ifndef PS_SIGN
#define PS_SIGN

#include <bits/stdc++.h>
#include <pbc.h>
#include <gmp.h>
#include "PS_Commit.h"
#include "util.h"

class PS_Sign{
    
    public:

        PS_Sign();
        void KeyGen(params pp, int num_of_attri,std::vector<element_s*> *vk,std::vector<element_s*> *sk);
        void Sign(params pp, std::vector<element_s*> *private_key, std::vector<element_s*> *message, std::vector<element_s*> *sign);
        bool Verify(params pp,std::vector<element_s*> *pub_key, std::vector<element_s*> *msg, std::vector<element_s*> *sign);


};
// struct ps_keys{
    
// };

#endif