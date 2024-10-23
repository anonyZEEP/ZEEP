#ifndef VEHICLE
#define VEHICLE
#include "Issuer.h"

class Vehicle {
public:
    Vehicle(); 
    void Setup(Issuer *I);

    std::pair<element_s*, std::tuple<element_s*, element_s*, element_s*>> Registration();
    bool Verify_Registration(std::tuple<std::pair<element_s*, element_s*>, std::pair<element_s*, element_s*>> req);

    std::tuple<std::tuple<element_s*,element_s*, element_s*,std::vector<element_s*>>, element_s*,element_s*, element_s*,element_s*,element_s*,std::vector<ZKP*>>
    Auth_to_DGSA();

    void Verify_Auth(std::tuple<std::pair<element_s*, element_s*>, std::pair<element_s*, element_s*>, std::vector<element_s*>> tok);




private:
    Issuer* IA;
    std::vector<element_s*> ticket_que;
    std::vector<element_s*> new_ticket_que;
    std::vector<std::pair<element_s*, element_s*>> witness;
    std::pair<element_s*, element_s*> commit;
    std::pair<element_s*, element_s*> new_commit;
    std::pair<element_s*, element_s*> sig_on_que;
    std::vector<element_s*> dgsa_sig;
    std::tuple<element_s*, element_s*, element_s*, element_s*> proof_params;
    std::tuple<element_s*, element_s*, element_s*> create_pi_reg();
    std::pair<unsigned char*, int> convert_to_byte(element_s* c, element_s* g, element_s* Y3);
    std::pair<unsigned char*, int> convert_to_byte(element_s* u, element_s* p1, element_s* p2, element_s* sig1, element_s* sig2, element_s* c1, element_s* c2);
    element_s* acc_val;
    std::tuple<element_s*,element_s*, element_s*,std::vector<element_s*>> Create_pi_c(element_s* r_d, element_s* si1,element_s* si2);
    
};

#endif
