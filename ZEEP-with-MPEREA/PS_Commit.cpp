#include "PS_Commit.h"
#include <bits/stdc++.h>

PSCommit::PSCommit() {

}

params PSCommit::Setup() {

    char param[1024];
    FILE *stream = fopen("f.param", "r");
    size_t count = fread(param, 1, 1024, stream);
    if (!count) pbc_die("input error");
    pp.e = (pairing_s*)malloc(sizeof(*(pp.e)));
    pairing_init_set_buf(pp.e, param, count);
    
    pp.p = (element_s*)malloc(sizeof(*(pp.p)));
    pp.G = (element_s*)malloc(sizeof(*(pp.G)));
    pp.G_bar = (element_s*)malloc(sizeof(*(pp.G_bar)));
    pp.G_T = (element_s*)malloc(sizeof(*(pp.G_T)));
    

    element_init_Zr(pp.p, pp.e);
    element_init_G1(pp.G, pp.e);
    element_init_G2(pp.G_bar, pp.e);
    element_init_GT(pp.G_T, pp.e);

    // element_random(pp.G);
    // element_random(pp.G_bar);

    int y = element_set_str(pp.G,"[1, 2]", 10);
    int g = element_set_str(pp.G_bar,"[[10857046999023057135944570762232829481370756359578518086990519993285655852781, 11559732032986387107991004021392285783925812861821192530917403151452391805634], [8495653923123431417604973247489272438418190587263600148770280649306958101930, 4082367875863433681332203403145435568316851327593401208105741076214120093531]]", 10);
    //int n = element_set_str(&)
    std::cout<<y<<" "<< g<<std::endl;
    return pp;

}

void PSCommit::KeyGen(int num_of_attri, params pp, element_s *sk, std::vector<element_s*> *vk) {

    std::vector<element_s> temp;

    char ans[1000];
    // element_s g, g_tilde;
    // element_init_G1(&g, &pp.e);
    // element_init_G2(&g_tilde, &pp.e);
    
    // element_random(&g);
    // element_random(&g_tilde);

    //printf("Address of vk is %p\n", (void *)vk->at(0)); 
    element_set(vk->at(0),pp.G);
    element_set((*vk).at(1),pp.G_bar);

    element_printf("G = %B\n\n",pp.G);
    element_printf("G_bar = %B\n\n",pp.G_bar);

    // vk.push_back(pp.G);
    // vk.push_back(pp.G_bar);

    // element_snprint(ans,sizeof(ans),&g);
    // std::cout<<"g "<<std::string(ans)<<std::endl;

    // element_snprint(ans,sizeof(ans),&g_tilde);
    // std::cout<<"g2 "<<std::string(ans)<<std::endl;

    
    for(int i=0;i<num_of_attri + 1;i++){
        element_s t;
        element_init_Zr(&t, pp.e);
        element_random(&t);
        
        temp.push_back(t);
        std::cout<<temp.size()<<std::endl;
        element_snprint(ans,sizeof(ans),&temp.at(i));
        std::cout<<"x y1 y2 "<<std::string(ans)<<std::endl;
    }

    element_init_G1(sk, pp.e);
    element_mul_zn(sk, vk->at(0), &temp.at(0));

    element_snprint(ans,sizeof(ans),sk);
    std::cout<<"sk "<<std::string(ans)<<std::endl;
    int count = 2;
    for(int i=0;i<num_of_attri;i++){
        element_s t;
        element_init_G1(&t, pp.e);
        element_mul_zn(&t, vk->at(0), &temp.at(i+1));

        element_snprint(ans,sizeof(ans),&t);
    std::cout<<"Y" + std::to_string(count-1) + " "<<std::string(ans)<<std::endl;
        element_set((*vk).at(count),&t);
        count++;
    }

    for(int i=0;i<num_of_attri + 1;i++){
        element_s t;
        element_init_G2(&t, pp.e);
        element_mul_zn(&t, vk->at(1), &temp.at(i));
        element_snprint(ans,sizeof(ans),&t);
    std::cout<<"Y_bar" + std::to_string(count-num_of_attri -1) + " "<<std::string(ans)<<std::endl;
        
        element_set((*vk).at(count),&t);
        count++;
    }
}

std::pair<element_s*, element_s*> PSCommit::GenCommitment(std::vector<element_s*> *msg, std::vector<element_s*> *public_key, params pp) {

        char ans[1000];
        element_s temp;
        element_s* C = (element_s *) malloc(sizeof(*C));
        element_s* r = (element_s *) malloc(sizeof(*r));
        element_init_Zr(r,pp.e);
        element_random(r);

        element_snprint(ans,sizeof(ans),r);
        std::cout<<"r = "<<std::string(ans)<<std::endl;

        element_init_G1(C, pp.e);
        element_init_G1(&temp, pp.e);
        element_mul_zn(C, public_key->at(0), r);
        element_snprint(ans,sizeof(ans),C);
    std::cout<<"g^r = "<<std::string(ans)<<std::endl;

        for(int i=2;i<(*msg).size() + 2;i++){
            element_mul_zn(&temp, public_key->at(i), msg->at(i-2));
            element_snprint(ans,sizeof(ans),&temp);
            std::cout<<" Y1 Y2 "<<std::string(ans)<<std::endl;
            element_add(C, C, &temp);
        }

        element_snprint(ans,sizeof(ans),C);
        std::cout<<" C "<<std::string(ans)<<std::endl;

        return std::make_pair(r,C);

}

std::pair<element_s*, element_s*> PSCommit::Sign(element_s* c, element_s* sk, element_s* epoch, std::vector<element_s*> *pub_key, params pp) {

        char ans[1000];
        element_s C_dash, temp, C;
        element_init_G1(&C,pp.e);
        element_set(&C, c);
        element_init_G1(&C_dash,pp.e);
        element_init_G1(&temp,pp.e);

        int index = 1 + ((*pub_key).size()-2)/2;
        element_printf("epoch = %B \n", epoch);
        element_printf("temp2 = %B \n", (*pub_key).at(index));
        element_mul_zn(&temp, (*pub_key).at(index), epoch);

        element_snprint(ans,sizeof(ans),&temp);
        std::cout<<" Y3^e "<<std::string(ans)<<std::endl;


        element_add(&C_dash, &C, &temp);

        element_snprint(ans,sizeof(ans),&C_dash);
        std::cout<<" C_dash "<<std::string(ans)<<std::endl;

        element_s u;
        element_s* sig1 = (element_s*) malloc(sizeof(*sig1));
        element_s* sig2 = (element_s*) malloc(sizeof(*sig2));
        element_init_Zr(&u, pp.e);
        element_init_Zr(&urr, pp.e);

        element_init_G1(sig1, pp.e);
        element_init_G1(sig2, pp.e);

        element_random(&u);
        element_snprint(ans,sizeof(ans),&u);
        std::cout<<"u "<<std::string(ans)<<std::endl;
        element_set(&urr, &u);
        element_mul_zn(sig1, pub_key->at(0), &u);
        element_snprint(ans,sizeof(ans),sig1);
        std::cout<<"sig1 "<<std::string(ans)<<std::endl;
        element_add(sig2, sk, &C_dash);
        element_mul_zn(sig2, sig2, &u);

        element_snprint(ans,sizeof(ans),sig2);
        std::cout<<"sig2 "<<std::string(ans)<<std::endl;

        return std::make_pair(sig1, sig2);
}

void PSCommit::Unblind(std::pair<element_s*, element_s*> sig, element_s* r, params pp) {
        
        char ans[1000];
        element_s temp, neg_r, a,b;
        element_init_G1(&temp, pp.e);
        element_init_Zr(&neg_r, pp.e);
        element_init_G1(&a, pp.e);
        element_init_G1(&b, pp.e);

        element_neg(&neg_r, r);
        element_snprint(ans,sizeof(ans),&neg_r);
        std::cout<<"neg_r "<<std::string(ans)<<std::endl;
        element_mul_zn(&temp , sig.first, &neg_r);

        element_snprint(ans,sizeof(ans),&temp);
        std::cout<<"sigma1^-r "<<std::string(ans)<<std::endl;
        //element_set(sig.first, &temp);
        // element_snprint(ans,sizeof(ans),&temp);
        // std::cout<<"neg_r "<<std::string(ans)<<std::endl;

        // element_div(&b, &sig.second, &temp);

        // element_snprint(ans,sizeof(ans),&b);
        // std::cout<<"brtyui "<<std::string(ans)<<std::endl;


        // element_snprint(ans,sizeof(ans),&neg_r);
        // std::cout<<"neg_r "<<std::string(ans)<<std::endl;

        element_add(&a, sig.second, &temp);
        element_set(sig.second, &a);
        element_snprint(ans,sizeof(ans),&a);
        std::cout<<"sigma2 "<<std::string(ans)<<std::endl;

        // element_snprint(ans,sizeof(ans),&sig.first);
        // std::cout<<"sig first "<<std::string(ans)<<std::endl;

}
bool PSCommit::Verify(std::pair<element_s*, element_s*> sig,std::vector<element_s*> msg, element_s* epoch, std::vector<element_s*> pub_key, params pp) {

    char ans[1000];
    element_s temp, temp2;
    element_init_G2(&temp, pp.e);
    element_init_G2(&temp2, pp.e);

    int index = pub_key.size() - msg.size() -2;
    std::cout<<index<<std::endl;
    element_set(&temp, pub_key.at(index));

    for(int i = 0; i<msg.size();i++){
        element_mul_zn(&temp2, pub_key.at(index+i+1), msg.at(i));
        element_add(&temp, &temp, &temp2);
    }
    element_mul_zn(&temp2, pub_key.at(index+msg.size()+1), epoch);
    element_add(&temp, &temp, &temp2);

    element_snprint(ans,sizeof(ans),&temp);
    std::cout<<"temp "<<std::string(ans)<<std::endl;

    element_s pai1,pai2;
    element_init_GT(&pai1,pp.e);
    element_init_GT(&pai2,pp.e);

    pairing_apply(&pai1,sig.first,&temp, pp.e);
    element_snprint(ans,sizeof(ans),&pai1);
    std::cout<<"pair1 "<<std::string(ans)<<std::endl;


    pairing_apply(&pai2,sig.second,pub_key.at(1),pp.e);

    element_snprint(ans,sizeof(ans),&pai2);
    std::cout<<"pair2 "<<std::string(ans)<<std::endl;


    return !element_cmp(&pai1, &pai2);

}