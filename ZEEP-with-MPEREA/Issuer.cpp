#include "Issuer.h"

std::pair<unsigned char*, int> Issuer::convert_to_byte(element_s* c, element_s* g, element_s* Y3){
    int size_c = element_length_in_bytes(c);
    unsigned char byte_c[size_c]; element_to_bytes(byte_c,c);

    int size_g = element_length_in_bytes(g);
    unsigned char byte_g[size_g]; element_to_bytes(byte_g,g);

    int size_y3 = element_length_in_bytes(Y3);
    unsigned char byte_y3[size_y3]; element_to_bytes(byte_y3,Y3);

    int total_size = size_c + size_g + size_y3;
    unsigned char* final_arr = new unsigned char[total_size];

    bzero(final_arr,total_size);
    memcpy(final_arr,byte_c,size_c);
    memcpy(final_arr+size_c,byte_g,size_g);memcpy(final_arr+size_c + size_g,byte_y3,size_y3);

    return std::make_pair(final_arr, total_size);

}

void init_pk(std::vector<element_s*> *arr, int size, params p){
    
    for(int i=0;i<2*size + 3;i++) {
        struct element_s* t = (element_s *)malloc(sizeof(*t));
        (*arr).push_back(t);
    }
    element_init_G1(arr->at(0), p.e);
    element_init_G2(arr->at(1), p.e);
    int count = 2;
    for(int i=0;i<size;i++){
        element_init_G1(arr->at(count), p.e);
        count++;
    }
    for(int i=0;i<size+1;i++){
        element_init_G2(arr->at(count), p.e);
        count++;
    }
}

Issuer::Issuer(){

}
void Issuer::Setup(int revoc_wind, int bl_size){

    K = revoc_wind;
    p = pscom.Setup();

    for(int i=0;i<bl_size;i++){
        element_s* defa = (element_s *) malloc(sizeof(*defa));;
        element_init_Zr(defa, p.e);
        element_random(defa);
        bl.push_back(defa);
    }
    t_cap = (element_s *) malloc(sizeof(*t_cap));
    element_init_Zr(t_cap, p.e);
    element_random(t_cap);
   // element_printf("t_cap    = %B\n\n",t_cap);
    sk_c = (element_s *) malloc(sizeof(*sk_c));
    init_pk(&pk_c, revoc_wind+1,p);
    element_init_G1(sk_c, p.e);

    pscom.KeyGen(revoc_wind+1, p, sk_c, &pk_c);

    pk_acc = (element_s *) malloc(sizeof(*pk_acc));
    sk_acc = (element_s *) malloc(sizeof(*sk_acc));
    acc_val = (element_s *) malloc(sizeof(*acc_val));
    element_init_G1(acc_val, p.e);
    element_set(acc_val, p.G);
    acc.KeyGen(p,pk_acc, sk_acc);

    dg.Setup(p, &psign_pk, &psign_sk);

    element_s* g1 = (element_s *) malloc(sizeof(*g1));
    element_init_G1(g1, p.e);
    element_set(g1, p.G);
    element_s* g_cap = (element_s *) malloc(sizeof(*g_cap));
    element_init_G1(g_cap, p.e);
    element_random(g_cap);
    element_s* h2 = (element_s *) malloc(sizeof(*h2));
    element_init_G2(h2, p.e);
    element_random(h2);
    element_s* h_cap = (element_s *) malloc(sizeof(*h_cap));
    element_init_G2(h_cap, p.e);
    element_random(h_cap);

    proof_params = std::make_tuple(g1, g_cap, h2, h_cap);
    // psign_pk = dg.ps_vk;
    // psign_sk = dg.ps_sk;
    // element_init_G1(&acc_val, &p.e);
    epoch = (element_s *) malloc(sizeof(*epoch));
    element_init_Zr(epoch, p.e);
    element_random(epoch);

    // element_init_G1(&t_cap, &p.e);
    // element_random(&t_cap);
}

std::tuple<std::pair<element_s*, element_s*>, std::pair<element_s*, element_s*>> 
Issuer::Register_User(std::pair<element_s*, std::tuple<element_s*, element_s*, element_s*>> req){
        
        element_s comm, temp;
        element_init_G1(&comm, p.e);
        element_init_G1(&temp, p.e);
        element_set(&comm, req.first);

        for(int i=2; i<K+1;i++){
            element_mul_zn(&temp, pk_c.at(i), t_cap);
            //element_printf("comm    = %B\n\n",&temp);
            element_sub(&comm, &comm, &temp);
            //element_printf("comm    = %B\n\n",&temp);
        }
        
        bool b = Verify_pi_reg(&comm, &req.second);

        
            std::pair<element_s*, element_s*> sig = pscom.Sign(req.first, sk_c, epoch, &pk_c,p);
            //element_printf(" one over here %B = \n", sig.first);
            element_s* w_a = (element_s*) malloc(sizeof(*w_a));
            element_s* w_b = (element_s*) malloc(sizeof(*w_b));
            std::pair<element_s*, element_s*> witness = std::make_pair(w_a, w_b); // witness t_cap
            acc.NonMemWithCreate(sk_acc, p, t_cap, &bl, &witness);

            
            return std::make_tuple(sig, witness);
        
}

bool Issuer::Verify_pi_reg(element_s* comm, std::tuple<element_s*, element_s*, element_s*> *tok){

    element_s temp, temp2, chall;
    element_init_G1(&temp, p.e);
    element_init_G1(&temp2, p.e);
    element_init_Zr(&chall, p.e);
    element_mul_zn(&temp, pk_c.at(0), std::get<1>(*tok));
    
    element_mul_zn(&temp2, pk_c.at(1 + K), std::get<2>(*tok));
    element_add(&temp, &temp, &temp2);
    element_mul_zn(&temp2, comm, std::get<0>(*tok));
    element_add(&temp2, &temp, &temp2);

    element_printf("u = %B\n\n",&temp2);

    std::pair<unsigned char*, int> by = convert_to_byte(&temp2, pk_c.at(0), pk_c.at(1+K));

    element_from_hash(&chall,by.first, by.second);
    bool ans = element_cmp(&chall, std::get<0>(*tok));
    delete [] by.first;
    delete[] std::get<0>(*tok);delete[] std::get<1>(*tok);delete[] std::get<2>(*tok);

    return ans;
}

std::tuple<std::pair<element_s*, element_s*>, std::pair<element_s*, element_s*>, std::vector<element_s*>> Issuer::Autheticate_User(std::tuple<std::tuple<element_s*,element_s*, element_s*,std::vector<element_s*>>, element_s*,element_s*, element_s*,element_s*,element_s*, 
std::vector<ZKP*>> tok)
{
    std::tuple<element_s*,element_s*, element_s*,std::vector<element_s*>> proof = std::get<0>(tok);
    element_s* challenge = std::get<0>(proof);
    element_s* sr1 = std::get<1>(proof);
    element_s* sr2 = std::get<2>(proof);
    element_s* c1 = std::get<1>(tok);
    element_s* c2 = std::get<2>(tok);
    element_s* si1 = std::get<3>(tok);
    element_s* si2 = std::get<4>(tok);
    element_s* t3 = std::get<5>(tok);
    std::vector<ZKP*> zkp = std::get<6>(tok);
    element_s pai4, temp, temp2, temp3, temp4, tzr;
    element_init_GT(&pai4, p.e);
    element_init_GT(&temp, p.e);
    element_init_G1(&temp2, p.e);
    element_init_G2(&temp3, p.e);
    element_init_G2(&temp4, p.e);
    element_init_Zr(&tzr, p.e);
    element_set1(&temp);
    for(int i=1;i<K;i++){
        element_mul_zn(&temp2, si1, std::get<3>(proof).at(i));
        pairing_apply(&pai4, &temp2, pk_c.at(3+K + i), p.e);
        element_mul(&temp, &temp, &pai4);
    }

    element_mul_zn(&temp2, si2, challenge);
    pairing_apply(&pai4, &temp2, pk_c.at(1), p.e);
    element_mul(&temp, &temp, &pai4);

    element_mul_zn(&temp2, si1, challenge);

    element_set_si(&tzr, -1);
    element_mul_zn(&temp3, pk_c.at(3+K),&tzr);
    element_mul_zn(&temp4, pk_c.at(pk_c.size()-2), t3);
    element_add(&temp3, &temp3, &temp4);
    element_mul_zn(&temp4, pk_c.at(pk_c.size()-1), epoch);
    element_add(&temp3, &temp3, &temp4);

    pairing_apply(&pai4, &temp2, &temp3, p.e);
    element_mul(&temp, &temp, &pai4);

    element_s c1_d, c2_d;
    element_init_G1(&c1_d, p.e);
    element_init_G1(&c2_d, p.e);
    element_neg(&tzr, t3);
    element_mul_zn(&temp2, pk_c.at(1+K), &tzr);
    element_add(&c1_d, std::get<1>(tok), &temp2);

    element_mul_zn(&temp2, pk_c.at(K), &tzr);
    element_add(&c2_d, std::get<2>(tok), &temp2);

    element_s p1, p2, temp5;
    element_init_G1(&p1, p.e);
    element_init_G1(&p2, p.e);
    element_init_G1(&temp5, p.e);
    element_mul_zn(&p1, &c1_d, challenge);
    element_mul_zn(&temp2, pk_c.at(0), sr1);
    element_add(&p1, &p1, &temp2);
    element_mul_zn(&p2, &c2_d, challenge);
    element_mul_zn(&temp5, pk_c.at(0), sr2);
    element_add(&p2, &p2, &temp5);

    for(int i=0;i<std::get<3>(proof).size()-1;i++){
    
        element_mul_zn(&temp2, pk_c.at(2 + i),std::get<3>(proof).at(i));
        element_add(&p1, &p1, &temp2);
        if(i == K-2) break;
        element_mul_zn(&temp5, pk_c.at(2 + i), std::get<3>(proof).at(i+1));
        element_add(&p2, &p2, &temp5);
    }
    element_mul_zn(&temp5, pk_c.at(2 + K), std::get<3>(proof).at(std::get<3>(proof).size()-1));
    element_add(&p2, &p2, &temp5);

    element_s challenge2;
    element_init_Zr(&challenge2, p.e);
    std::pair<unsigned char*, int> cc = convert_to_byte(&temp, &p1, &p2, si1, si2,c1, c2);

    element_from_hash(&challenge2,cc.first, cc.second);

    bool ans = element_cmp(challenge, &challenge2);
    bool ans2 = true;
    for(int i=0;i<zkp.size();i++){
        std::tuple<element_s*,element_s*,element_s*,element_s*,element_s*,element_s*,element_s*,element_s*,element_s*,
                    element_s*,element_s*> abc = std::make_tuple(zkp.at(i)->A2,zkp.at(i)->B1, zkp.at(i)->B2, zkp.at(i)->CI, zkp.at(i)->challenge, zkp.at(i)->sr, zkp.at(i)->st1, zkp.at(i)->st3, zkp.at(i)->st4, zkp.at(i)->sd3, zkp.at(i)->sd4); 
        ans2 = ans2 & acc.VerifyZKP(p,&abc, &proof_params, acc_val);
    }
    
        std::pair<element_s*, element_s*> sig = pscom.Sign(std::get<2>(tok), sk_c, epoch, &pk_c,p);
        element_s* w_a = (element_s*) malloc(sizeof(*w_a));
        element_s* w_b = (element_s*) malloc(sizeof(*w_b));
        std::pair<element_s*, element_s*> witness = std::make_pair(w_a, w_b); // witness t_cap
        acc.NonMemWithCreate(sk_acc, p, std::get<5>(tok), &bl, &witness);
        
        element_s* id = (element_s*) malloc(sizeof(*id));
        element_init_Zr(id, p.e);
        element_set(id, t3);
        element_s* ep = (element_s*) malloc(sizeof(*ep));
        element_init_Zr(ep, p.e);
        element_set(ep, epoch);
        element_s* e = (element_s*) malloc(sizeof(*e));
        element_init_Zr(e, p.e);
        element_s* r = (element_s*) malloc(sizeof(*r));
        element_init_Zr(r, p.e);
        element_s* t = (element_s*) malloc(sizeof(*t));
        element_init_Zr(t, p.e);
        std::vector<element_s*> pq;
        pq.push_back(e); pq.push_back(r); pq.push_back(t);

        dg.Issuer_DGSA(p, &psign_sk,&wl,id,ep,&pq);


        delete cc.first;
        delete challenge;
        delete sr1;
        delete sr2;
        delete c1;
        delete c2;
        delete si1;
        delete si2;
        delete c1;
        delete c2;
        
        // delete std::get<0>(std::get<6>(tok));
        // delete std::get<1>(std::get<6>(tok));
        // delete std::get<2>(std::get<6>(tok));
        // delete std::get<3>(std::get<6>(tok));
        // delete std::get<4>(std::get<6>(tok));
        // delete std::get<5>(std::get<6>(tok));
        // delete std::get<6>(std::get<6>(tok));
        // delete std::get<7>(std::get<6>(tok));
        // delete std::get<8>(std::get<6>(tok));
        // delete std::get<9>(std::get<6>(tok));
        // delete std::get<10>(std::get<6>(tok));

        // delete std::get<0>(std::get<7>(tok));
        // delete std::get<1>(std::get<7>(tok));
        // delete std::get<2>(std::get<7>(tok));
        // delete std::get<3>(std::get<7>(tok));
        // delete std::get<4>(std::get<7>(tok));
        // delete std::get<5>(std::get<7>(tok));
        // delete std::get<6>(std::get<7>(tok));
        // delete std::get<7>(std::get<7>(tok));
        // delete std::get<8>(std::get<7>(tok));
        // delete std::get<9>(std::get<7>(tok));
        // delete std::get<10>(std::get<7>(tok));

        return std::make_tuple(sig, witness, pq);
    

}

std::pair<unsigned char*, int> Issuer::convert_to_byte(element_s* u, element_s* p1, element_s* p2, element_s* sig1, element_s* sig2, element_s* c1, element_s* c2){
    int size_u = element_length_in_bytes(u);
    unsigned char byte_u[size_u]; element_to_bytes(byte_u,u);

    int size_p1 = element_length_in_bytes(p1);
    unsigned char byte_p1[size_p1]; element_to_bytes(byte_p1,p1);

    int size_p2 = element_length_in_bytes(p2);
    unsigned char byte_p2[size_p2]; element_to_bytes(byte_p2,p2);

    int size_sig1 = element_length_in_bytes(sig1);
    unsigned char byte_sig1[size_sig1]; element_to_bytes(byte_sig1,sig1);

    int size_sig2 = element_length_in_bytes(sig2);
    unsigned char byte_sig2[size_sig2]; element_to_bytes(byte_sig2,sig2);

    int size_c1 = element_length_in_bytes(c1);
    unsigned char byte_c1[size_c1]; element_to_bytes(byte_c1,c1);

    int size_c2 = element_length_in_bytes(c2);
    unsigned char byte_c2[size_c2]; element_to_bytes(byte_c2,c2);


    int total_size = size_u + size_p1 + size_p2 + size_sig1 + size_sig2 + size_c1 + size_c1;
    unsigned char* final_arr = new unsigned char[total_size];

    bzero(final_arr,total_size);
    memcpy(final_arr,byte_u,size_u);
    memcpy(final_arr+size_u,byte_p1,size_p1);memcpy(final_arr+size_u+ size_p1,byte_p2,size_p2);
    memcpy(final_arr+size_u+ size_p1 + size_p2,byte_sig1,size_sig1);
    memcpy(final_arr+size_u+ size_p1 + size_p2 + size_sig1,byte_sig2,size_sig2);
    memcpy(final_arr+size_u+ size_p1 + size_p2 + size_sig1 + size_sig2,byte_c1,size_c1);
    memcpy(final_arr+size_u+ size_p1 + size_p2 + size_sig1 + size_sig2 + size_c1,byte_c2,size_c2);


    return std::make_pair(final_arr, total_size);
}
