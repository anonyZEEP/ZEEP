#include "DGSA.h"

std::pair<byte*, int> DGSA::convert_to_byte( element_s* u, element_s* epoch, element_s* msg1,element_s* msg2,byte* msg3,element_s* sig1, 
                element_s* sig2, std::vector<element_s*> *vk){
    int size_u = element_length_in_bytes(u);
    byte byte_u[size_u]; element_to_bytes(byte_u,u);
    
    //print_text(byte_u,size_u);
    int size_epoch = element_length_in_bytes(epoch);
    byte byte_epoch[size_epoch]; element_to_bytes(byte_epoch,epoch);

    //print_text(byte_epoch,size_epoch);

    int size_msg1 = element_length_in_bytes(msg1);
    byte byte_msg1[size_msg1]; element_to_bytes(byte_msg1,msg1);

    //print_text(byte_msg1,size_msg1);

    int size_msg2 = element_length_in_bytes(msg2);
    byte byte_msg2[size_msg2]; element_to_bytes(byte_msg2,msg2);

    //print_text(byte_msg2,size_msg2);
    int size_msg3 = 16;
    byte byte_msg3[size_msg3]; memcpy(&byte_msg3, msg3, size_msg3);

   // print_text(byte_msg3,size_msg3);

    int size_sig1 = element_length_in_bytes(sig1);
    byte byte_sig1[size_sig1]; element_to_bytes(byte_sig1,sig1);
   // print_text(byte_sig1,size_sig1);
    int size_sig2 = element_length_in_bytes(sig2);
    byte byte_sig2[size_sig2]; element_to_bytes(byte_sig2,sig2);
    //print_text(byte_sig2,size_sig2);
    int pk_size = 0;
    for(int i=0;i<(*vk).size();i++){
        pk_size+=element_length_in_bytes((*vk).at(i));
    }
    byte byte_pk[pk_size];
    int curr_read = 0;
    for(int i=0;i<(*vk).size();i++){
        curr_read+=element_to_bytes(byte_pk + curr_read, (*vk).at(i));
    }
    //print_text(byte_pk,pk_size);
    int total_size = size_u + size_epoch + size_msg1 + size_msg2 + size_msg3 + size_sig1 + size_sig2 + pk_size;
    byte* final_arr = new byte[total_size];

    bzero(final_arr,total_size);
    memcpy(final_arr,byte_u,size_u);memcpy(final_arr+size_u,byte_epoch,size_epoch);
    memcpy(final_arr+size_u+size_epoch,byte_msg1,size_msg1);memcpy(final_arr+size_u+size_epoch + size_msg1,byte_msg2,size_msg2);
    memcpy(final_arr+size_u+size_epoch + size_msg1 + size_msg2 ,byte_msg3,size_msg3);memcpy(final_arr+size_u+size_epoch + size_msg1 + size_msg2 + size_msg3,byte_sig1,size_sig1);
    memcpy(final_arr+size_u+size_epoch + size_msg1 + size_msg2 + size_msg3 + size_sig1,byte_sig2,size_sig2);memcpy(final_arr+size_u+size_epoch + size_msg1 + size_msg2 + size_msg3 + size_sig1 + size_sig2,byte_pk,pk_size);
    
    //print_text(final_arr,total_size);

    std::cout<<"Over here"<<std::endl;
    return std::make_pair(final_arr, total_size);
}
void DGSA::print_text(byte text[],int size){
    std::string encoded;

    encoded.clear();
	StringSource(text, size, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	std::cout << "Hexcoded: " << encoded << std::endl;
}

DGSA::DGSA() {

        

}
void DGSA::Setup(params p, std::vector<element_s*> *ps_vk, std::vector<element_s*> *ps_sk){
        // change this static values
        for(int i=0;i<4;i++){
                element_s* t = (element_s *) malloc(sizeof(*t));
                element_init_Zr(t, p.e);
                // element_random(&t);
                // element_random(&a);
                (*ps_sk).push_back(t);
        }
        for(int i=0;i<5;i++){
                element_s* a = (element_s *) malloc(sizeof(*a));
                element_init_G2(a, p.e);
                // element_random(&t);
                // element_random(&a);
                (*ps_vk).push_back(a);
        }
        ps.KeyGen(p, 2, ps_vk, ps_sk);
        element_printf("inside = %B\n\n",(*ps_sk).at(0));
}
 
void DGSA::Issuer_DGSA(params p,std::vector<element_s*> *sk,std::vector<std::tuple<element_s*, element_s*, element_s*> > *st, 
                         element_s* id, element_s* epoch, std::vector<element_s*> *sign){
            
            std::vector<element_s*> msg;
            msg.push_back(id); msg.push_back(epoch);
            std::cout<<"herer"<<std::endl;
            ps.Sign(p, sk, &msg, sign);
            

            (*st).push_back(std::make_tuple(id, epoch, (*sign).at(0)));
}

void DGSA::Vehicle_DGSA(params p, element_s id, element_s epoch, std::vector<element_s*> *vk,std::vector<element_s*> *sign,
                            std::tuple<element_s, element_s , element_s, element_s, element_s> *cred){
                std::vector<element_s*> msg;
                msg.push_back(&id);
                msg.push_back(&epoch);   
                if(ps.Verify(p, vk, &msg, sign)){
                    std::cout<<"verified"<<std::endl;
                }

                element_set(&std::get<0>(*cred), &id);
                element_set(&std::get<1>(*cred), &epoch);
                element_set(&std::get<2>(*cred), (*sign).at(0));
                element_set(&std::get<3>(*cred), (*sign).at(1));
                element_set(&std::get<4>(*cred), (*sign).at(2));

                // (*cred).first.second = epoch;
                // (*cred).second = (*sign);

}

void DGSA::Auth(std::vector<element_s*> *vk,std::tuple<element_s, element_s , element_s, element_s, element_s> *cred,
                 std::tuple<element_s, element_s, std::pair<element_s, byte*> > *msg, 
                 std::tuple< element_s, element_s, element_s, element_s, element_s> *tok, params p){
                

        element_s r, S_id, S_a_dash;
        element_init_Zr(&r, p.e);
        element_init_Zr(&S_id, p.e);
        element_init_Zr(&S_a_dash, p.e);
        element_random(&r);element_random(&S_id);element_random(&S_a_dash);
        element_printf("sigma_1 = %B\n\n",&std::get<3>(*cred));
        
        element_printf("sigma_2 = %B\n\n",&std::get<4>(*cred));
        element_mul_zn(&std::get<0>(*tok), &std::get<3>(*cred), &r);
        element_mul_zn(&std::get<1>(*tok), &std::get<4>(*cred), &r);
        
        element_s temp1, temp2;
        element_init_G1(&temp1, p.e);
        element_init_G1(&temp2, p.e);

        element_mul_zn(&temp1, &std::get<0>(*tok), &S_id);
        element_mul_zn(&temp2, &std::get<0>(*tok), &S_a_dash);
        element_printf("sigma_1_dash_mul_S_id = %B\n\n",&temp1);
        element_printf("sigma_1_dash_mul_S_a = %B\n\n",&temp2);
        // element_printf("temp1 = %B\n\n", &temp1);
        // element_printf("temp2 = %B\n\n", &temp2);
        element_s pai1,pai2, u;
        element_init_GT(&pai1,p.e);
        element_init_GT(&pai2,p.e);
        element_init_GT(&u,p.e);

        element_printf("pk[0] = %B\n\n",(*vk)[0]);
        element_printf("pk[1] = %B\n\n",(*vk)[1]);
        element_printf("pk[2] = %B\n\n",(*vk)[2]);
        element_printf("pk[3] = %B\n\n",(*vk)[3]);
        element_printf("pk[4] = %B\n\n",(*vk)[4]);
        pairing_apply(&pai1,&temp1,(*vk)[2], p.e);

        pairing_apply(&pai2,&temp2,(*vk)[(*vk).size() -1] ,p.e);

        element_mul(&u, &pai1, &pai2);
        element_printf("u = %B \n\n",&u);

        //std::tuple<element_s,int, tuple<int,int,pair<element_s, element_s>>,element_s, element_s,vector<element_s>> challenge = make_tuple(u,c.first.second, message, sigma_1_dash, sigma_2_dash, pk_i);
        

        std::pair<byte*, int> serialize = convert_to_byte(&u,&std::get<1>(*msg),&std::get<0>(*msg),&std::get<2>(*msg).first,std::get<2>(*msg).second,&std::get<0>(*tok) ,&std::get<1>(*tok), vk);
    
        element_from_hash(&std::get<2>(*tok), serialize.first, serialize.second);
        element_printf("hash = %B \n\n",&std::get<2>(*tok));
//        // print_text(serialize.first,serialize.second);
           delete[] serialize.first;
        element_s temp3, temp4;
        element_init_Zr(&temp3, p.e);
        element_init_Zr(&temp4, p.e);
        // element_init_Zr(&temp5, &p.e);
        // element_init_Zr(&temp6, &p.e);
        element_printf("s_id = %B\n\n",&S_id);
        element_printf("c = %B\n\n",&std::get<2>(*tok));
        // element_snprint(ans,sizeof(ans),&id_s);
        // cout<<"id_s = "<<string(ans)<<endl;

        element_mul(&temp3,&std::get<2>(*tok), &std::get<0>(*cred));
        element_printf("cid = %B\n\n",&temp3);
        element_mul(&temp4,&std::get<2>(*tok), &std::get<2>(*cred));
        //element_printf("m_dash = %B\n\n", &c.second.first.first);
        element_sub(&std::get<3>(*tok), &S_id , &temp3);
        //element_printf("result = %B\n\n",&temp5);
        element_sub(&std::get<4>(*tok), &S_a_dash , &temp4);
        //element_printf("result2 = %B\n\n",&temp6);
        // pair<element_s, element_s> verify = make_pair(temp5, temp6);
        // pair<element_s, pair<element_s, element_s>> pie = make_pair(challenge_hash, verify);

        
        // cout<<"A = "<<c.first.second<<endl;

        // element_printf("m_sig_1 = %B\n\n",&get<2>(message).first);
        // element_printf("m_sig_2 = %B\n\n",&get<2>(message).second);
        // element_printf("sig_1 = %B\n\n",&sigma_1_dash);
        // element_printf("sig_2 = %B\n\n",&sigma_2_dash);
        // cout<<"Public key while signing"<<endl;
        // for(auto i = pk_i.begin();i!=pk_i.end();i++){
        //     element_printf("%B\n\n",i);
        // }
//         return make_tuple(sigma_1_dash, sigma_2_dash, pie);

}

bool DGSA::Verify(std::vector<element_s*> *vk, std::tuple<element_s, element_s, std::pair<element_s, byte*> > *msg, element_s epoch, 
           std::tuple< element_s, element_s, element_s, element_s, element_s> *tok, params p){

         std::cout<<"This is DGSA verify"<<std::endl;
         element_s temp1,temp2,temp3,temp4;
         element_init_G1(&temp1, p.e);
         element_init_G1(&temp2, p.e);
         element_init_G1(&temp3, p.e);
         element_init_G1(&temp4, p.e);

         element_mul_zn(&temp1, &std::get<0>(*tok), &std::get<3>(*tok)); // sigma1 vid
         element_mul_zn(&temp2, &std::get<0>(*tok), &std::get<4>(*tok)); // sigma1 va'
         element_mul_zn(&temp3, &std::get<1>(*tok), &std::get<2>(*tok)); // sigma2 c 
         element_mul_zn(&temp4, &std::get<0>(*tok), &std::get<2>(*tok)); // sigma1 c


         element_printf("vid = %B\n\n",&std::get<3>(*tok));
         element_printf("va = %B\n\n",&std::get<4>(*tok));
         element_printf("hash = %B\n\n",&std::get<2>(*tok));
         element_printf("sigma_1 = %B\n\n",&std::get<0>(*tok));
         element_printf("sigma_2 = %B\n\n",&std::get<1>(*tok));

         element_s inv_X, inv_ep, temp5, temp6, epoch_s, neg_epoch, neg_one;
         element_init_G2(&inv_X, p.e);
         element_init_G2(&inv_ep, p.e);
         element_init_G2(&temp5, p.e);
         element_init_G2(&temp6, p.e);
         element_init_Zr(&epoch_s, p.e);
         element_init_Zr(&neg_epoch, p.e);
         element_init_Zr(&neg_one, p.e);
         element_set(&epoch_s, &epoch);
         element_set_si(&neg_one, -1);
         element_printf("neg_one = %B\n\n",&neg_one);

         
         //char ans[1000];

        // element_snprint(ans,sizeof(ans),&epoch_s);
        //std::cout<<"epoch = "<<epoch<<std::endl;
            element_neg(&neg_epoch, &epoch_s);
            element_printf("neg_epoch = %B\n\n",&neg_epoch);
        //  element_pow_zn(&temp5, &pk_i[3], &neg_epoch);
        element_mul_zn(&inv_X, (*vk).at(1), &neg_one);
         //element_invert(&inv_X, &pk_i[1]);
         //element_invert(&inv_ep, &pk_i[3]);
        element_mul_zn(&temp5, (*vk).at(3), &neg_epoch);
        element_add(&temp6, &inv_X, &temp5);
        
        element_s pai1,pai2,pai3,pai4,u, temp7;
        element_init_GT(&pai1,p.e);
        element_init_GT(&pai2,p.e);
        element_init_GT(&pai3,p.e);
        element_init_GT(&pai4,p.e);
        element_init_GT(&temp7,p.e);
        element_init_GT(&u,p.e);

        pairing_apply(&pai1,&temp1,(*vk).at(2), p.e);

        pairing_apply(&pai2,&temp2,(*vk).at((*vk).size()-1) ,p.e);
        pairing_apply(&pai3,&temp3,(*vk).at(0) ,p.e);
        pairing_apply(&pai4,&temp4,&temp6 ,p.e);

        element_mul(&temp7, &pai1, &pai2);
        element_mul(&temp7, &temp7, &pai3);
        element_mul(&u, &temp7, &pai4);

        element_printf("u = %B \n\n",&u);

        std::pair<byte*, int> serialize = convert_to_byte(&u,&std::get<1>(*msg),&std::get<0>(*msg),&std::get<2>(*msg).first,std::get<2>(*msg).second,&std::get<0>(*tok) ,&std::get<1>(*tok), vk);

//         tuple<element_s,int, tuple<int,int,pair<element_s, element_s>>,element_s, element_s,vector<element_s>> challenge = make_tuple(u,epoch, message, std::get<0>(tok), std::get<1>(tok), pk_i);
//         // element_snprint(ans,sizeof(ans),&u);
//         // cout<<"u_v = "<<string(ans)<<endl;
        
        element_s challenge_hash;
        element_init_Zr(&challenge_hash, p.e);
//         pair<byte*, int> serialize = convert_to_byte(challenge);
//        // print_text(serialize.first,serialize.second);
//     //     std::cout << std::hex << std::setfill('0') ;
//     // for( byte b : serialized ) std::cout << std::setw(2) << int(b) << ' ' ;
//     // std::cout << '\n' ;
        element_from_hash(&challenge_hash, serialize.first, serialize.second);
        element_printf("c = %B\n\n",&challenge_hash);
//         delete [] serialize.first;
//         element_printf("u = %B \n\n",&u);
//         // cout<<"A = "<<epoch<<endl;
//         // element_printf("m_sig_1 = %B\n\n",&std::get<2>(message).first);
//         // element_printf("m_sig_2 = %B\n\n",&std::get<2>(message).second);
//         // element_printf("sig_1 = %B\n\n",&std::get<0>(tok));
//         // element_printf("sig_2 = %B\n\n",&std::get<1>(tok));
//         // cout<<"Public key while verifying"<<endl;
//         // for(auto i = pk_i.begin();i!=pk_i.end();i++){
//         //     element_printf("%B\n\n",i);
//         // }
//         // element_snprint(ans,sizeof(ans),&challenge_hash);
//         // cout<<"x = "<<string(ans)<<endl;
//         // element_snprint(ans,sizeof(ans),&std::get<2>(tok).first);
//         // cout<<"y = "<<string(ans)<<endl;
        return !element_cmp(&challenge_hash, &std::get<2>(*tok));

}

