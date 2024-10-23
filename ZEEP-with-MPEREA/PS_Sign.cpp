#include "PS_Sign.h"

PS_Sign::PS_Sign(){
    // char param[1024];
    // FILE *stream = fopen("f.param", "r");
    // size_t count = fread(param, 1, 1024, stream);
    // if (!count) pbc_die("input error");
    
    // pairing_init_set_buf(&pp.e, param, count);

    // element_init_Zr(&pp.p, &pp.e);
    // element_init_G1(&pp.G, &pp.e);
    // element_init_G2(&pp.G_bar, &pp.e);
    // element_init_GT(&pp.G_T, &pp.e);

    // int y = element_set_str(&pp.G,"[1, 2]", 10);
    // int g = element_set_str(&pp.G_bar,"[[10857046999023057135944570762232829481370756359578518086990519993285655852781, 11559732032986387107991004021392285783925812861821192530917403151452391805634], [8495653923123431417604973247489272438418190587263600148770280649306958101930, 4082367875863433681332203403145435568316851327593401208105741076214120093531]]", 10);
    // //int n = element_set_str(&)
    // std::cout<<y<<" "<< g<<std::endl;

}
void PS_Sign::KeyGen(params pp, int num_of_attri, std::vector<element_s*> *vk,std::vector<element_s*> *sk){

        // std::vector<element_s> vk;
        // std::vector<element_s> sk;
        //element_s g2,x, g2X, y, g2Y;
        //struct element_s* g2 = (struct element_s*)malloc(sizeof(element_t));
        // element_init_Zr(&x, &pp.e);
        // element_init_G2(&g2, &pp.e);
        // element_init_G2(&g2X, &pp.e);
        element_random((*vk)[0]);
        element_printf("g2 = %B\n\n",(*vk)[0]);
        element_random((*sk)[0]);
        element_printf("x = %B\n\n",(*sk)[0]);
        element_mul_zn((*vk)[1], (*vk)[0], (*sk)[0]);
        element_printf("g2X = %B\n\n",(*vk)[1]);
        // (*vk)[0] = g2;
        // (*sk)[0] = x;
        // (*vk)[1] = g2X;
        for(int i=0;i<=num_of_attri;i++){
            // element_init_Zr(&y,&pp.e);
            // element_init_G2(&g2Y, &pp.e);
            element_random((*sk)[i+1]);
            element_printf("y = %B\n\n",(*sk)[i+1]);
            element_mul_zn((*vk)[i+2], (*vk)[0],(*sk)[i+1]);
            element_printf("g2Y = %B\n\n",(*vk)[i+2]);
            // (*sk)[i+1] = y;
            // (*vk)[i+2] = g2Y;
        }

        // return std::make_pair(sk, vk);

}
void PS_Sign::Sign(params pp, std::vector<element_s*> *private_key, std::vector<element_s*> *message, std::vector<element_s*> *sign){
        element_s h, m_dash, sigg, temp, temp2;
        element_init_Zr(&temp2, pp.e);
        element_init_G1(&h, pp.e);
        element_init_G1(&sigg, pp.e);
        element_init_Zr(&m_dash, pp.e);
        element_init_Zr(&temp, pp.e);
        element_random(&h);
        element_random(&m_dash);
        element_set(&temp, (*private_key).at(0));

        for(int i=0;i<(*message).size();i++){
            
            
            // cout<<size[i]<<endl;
            //print_text(message[i], size[i]);
            element_printf("temp2 = %B\n\n",((*message).at(i)));
            element_printf("temp2 = %B\n\n",((*private_key).at(i+1)));
            element_mul(&temp2,((*message).at(i)),((*private_key).at(i+1)));
            element_printf("temp2 = %B\n\n",&temp2);
            element_add(&temp,&temp,&temp2);
       }
    //    element_s temp2;
    //    element_init_Zr(&temp2, &pp.e);
       element_mul(&temp2,&m_dash,(*private_key).at((*message).size()+1));
       element_printf("temp2 = %B\n\n",&temp2);
       
       element_add(&temp,&temp,&temp2);
       element_printf("temp2 = %B\n\n",&temp);
       
       element_mul_zn(&sigg, &h, &temp);

       element_printf("m_dash = %B\n\n",&m_dash);
       element_printf("h = %B\n\n",&h);
       element_printf("sig = %B\n\n",&sigg);
       
       element_set((*sign).at(0),&m_dash);
       element_set((*sign).at(1),&h);
       element_set((*sign).at(2),&sigg);
        //signat->assign_val(&m_dash, &h, &sigg, pp);
    //    (*signat).push_back(h);
    //    (*signat).push_back(sig);
        element_clear(&h);
        element_clear(&m_dash);
        element_clear(&sigg);
        element_clear(&temp);
        element_clear(&temp2);

}


bool PS_Sign::Verify(params pp,std::vector<element_s*> *pub_key, std::vector<element_s*> *msg, std::vector<element_s*> *sign){

        element_s mult, temp;
        element_init_G2(&temp,pp.e);
        element_init_G2(&mult,pp.e);

        element_set(&mult, (*pub_key).at(1));

       
        for(int i=0;i<(*msg).size();i++){
            
            

            element_mul_zn(&temp,(*pub_key).at(i+2),(*msg).at(i));
            element_add(&mult,&mult, &temp);
       }

    //    element_s temp;
    //    element_init_G2(&temp,&pp.e);
       element_mul_zn(&temp,(*pub_key).at((*pub_key).size() -1),(*sign).at(0));
       element_add(&mult, &mult,&temp);
       element_printf("mult = %B\n\n",&mult);

        element_s pai1,pai2;
        element_init_GT(&pai1,pp.e);
        element_init_GT(&pai2,pp.e);

        pairing_apply(&pai1,(*sign).at(1),&mult,pp.e);

        pairing_apply(&pai2,(*sign).at(2),(*pub_key).at(0) ,pp.e);

        element_printf("pai1 = %B\n\n",&pai1);
        element_printf("pai2 = %B\n\n",&pai2);

        // char ans[1000];
        // element_snprint(ans,sizeof(ans),&pai1);
        // cout<<"x = "<<string(ans)<<endl;
        // element_snprint(ans,sizeof(ans),&pai2);
        // cout<<"y = "<<string(ans)<<endl;
        element_clear(&mult);
        element_clear(&temp);
        if (!element_cmp(&pai1, &pai2)) {
            element_clear(&pai1);
            element_clear(&pai2);
            printf("signature verifies\n");
            return true;
        } else {
            element_clear(&pai1);
            element_clear(&pai2);
            printf("signature does not verify\n");
            return false;
        }

}