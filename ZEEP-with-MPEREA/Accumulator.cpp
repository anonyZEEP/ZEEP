#include "Accumulator.h"

Accumulator::Accumulator() {

}

void Accumulator::Setup(){


}

void Accumulator::print_text(byte text[],int size){
    std::string encoded;

    encoded.clear();
	StringSource(text, size, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	std::cout << "Hexcoded: " << encoded << std::endl;
}
void Accumulator::KeyGen(params pp, element_s *vk, element_s *sk){

    element_init_Zr(sk, pp.e);
    element_random(sk);
    element_init_G2(vk, pp.e);
    element_mul_zn(vk, pp.G_bar, sk);
    
}
void Accumulator::Add(element_s* sk, params pp, element_s* x, element_s* delta) {
    element_s temp;
    element_init_Zr(&temp, pp.e);
    element_add(&temp, x, sk);
    element_mul_zn(delta, delta, &temp);

}

void Accumulator::Delete(element_s* sk, params pp, element_s* x, element_s* delta) {
    element_s temp;
    element_init_Zr(&temp, pp.e);
    element_add(&temp, x, sk);
    element_invert(&temp, &temp);
    element_mul_zn(delta, delta, &temp);

    element_clear(&temp);

}
// void Accumulator::getWitness(element_s* x, element_s* prod, params p){
//     element_s ran, one, mult, B;
//     element_init_Zr(&ran, p.e);
//     element_init_Zr(&one, p.e);
//     element_init_Zr(&mult, p.e);
//     element_init_Zr(&B, p.e);
//     element_random(&ran);
//     element_printf("A  = %B", &ran);
//     element_mul(&mult, &ran, prod);
//     element_set_si(&one, 1);
//     element_sub(&mult,&one, &mult);
//     element_div(&B, &mult, x);

//     element_printf("B  = %B\n", &B);


//     element_s temp2, temp3;
//     element_init_Zr(&temp2, p.e);
//     element_init_Zr(&temp3, p.e);
//     element_mul(&temp2, &ran, prod);
//     element_mul(&temp3, &B, x);
//     element_add(&temp2, &temp2, &temp3);
//     element_printf("ans  = %B", &temp2);

// }

void Accumulator::NonMemWithCreate(element_s* sk, params pp, element_s* x, std::vector<element_s*> *wl, std::pair<element_s*, element_s*> *witness){
        element_s u, temp2, dd, temp;
        element_s k;
        //mpz_t z, h,n;
        element_s t3, t4;
        element_init_Zr(&u, pp.e);
        element_set1(&u);
        element_init_Zr(&temp2, pp.e);
        element_init_Zr(&temp, pp.e);
        element_init_Zr(&dd, pp.e);
        element_set1(&dd);
        for(int i=0;i<(*wl).size();i++){
            element_add(&temp2, sk, (*wl).at(i));
            element_sub(&temp, (*wl).at(i), x);
            element_mul(&u, &u,&temp2);
            element_mul(&dd, &dd, &temp);
        }
        element_printf("u =  %B\n", &u);
        element_printf("dd =  %B\n", &dd);
    
        element_init_Zr(&k, pp.e);
        element_init_Zr(witness->second, pp.e);
        element_add(&k, x,sk);

        
        // mpz_init(z);mpz_init(h);mpz_init(n);
        // element_to_mpz(z, &u);
        // element_to_mpz(h,&k);
        // mpz_mod(n, z,h);
        // element_set_mpz(witness->second,n);
        element_set(witness->second, &dd);
        element_printf("d =  %B\n", witness->second);
        // element_snprint(ans,sizeof(ans),witness->second);
        // std::cout<<"d "<<std::string(ans)<<std::endl;

        
        element_init_Zr(&t3, pp.e);
        element_init_G1(witness->first, pp.e);
        element_sub(&t3, &u, witness->second);

        element_printf("u-d =  %B\n", &t3);
        // element_snprint(ans,sizeof(ans),&t3);
        // std::cout<<"u-d "<<std::string(ans)<<std::endl;

        element_mul_zn(witness->first, pp.G, &t3);

        element_printf("g^(u-r) =  %B\n", witness->first);
        // element_snprint(ans,sizeof(ans),witness->first);
        // std::cout<<"g^(u-r) "<<std::string(ans)<<std::endl;
        element_invert(&k,&k);
        element_mul_zn(witness->first, witness->first, &k);
        element_printf("g^((u-r)/(x+a)) =  %B\n", witness->first);
        // element_snprint(ans,sizeof(ans),&t4);
        // std::cout<<"g^((u-r)/(x+a)) "<<std::string(ans)<<std::endl;
        element_neg(witness->second, witness->second);
        element_printf("d =  %B\n", witness->second);

        // element_snprint(ans,sizeof(ans),witness->second);
        // std::cout<<"d "<<std::string(ans)<<std::endl;
        element_clear(&u);
        element_clear(&temp2);
        element_clear(&k);
        element_clear(&t3);
        //mpz_clear(z);mpz_clear(h);mpz_clear(n);


        //return std::make_pair(t4,d);
}

bool Accumulator::VerNonMem(params pp, element_s* x, std::pair<element_s*, element_s*> *witness, element_s* pub, element_s* delta){
    
    element_s pai1,pai2, pai3;
    element_init_GT(&pai1,pp.e);
    element_init_GT(&pai2,pp.e);
    element_init_GT(&pai3,pp.e);
    element_s tt;
    element_init_G2(&tt, pp.e);

    element_printf("delta = %B\n\n",delta);

    pairing_apply(&pai1,delta,pp.G_bar, pp.e);
    pairing_apply(&pai2,pp.G,pp.G_bar,pp.e);
    element_mul_zn(&pai2, &pai2, witness->second);
    element_mul_zn(&tt, pp.G_bar, x);
    element_add(&tt, &tt, pub);
    pairing_apply(&pai3, witness->first, &tt, pp.e);

    element_mul(&pai1, &pai1, &pai2);

    element_printf("pai3 = %B\n\n",&pai3);
    element_printf("pai1 = %B\n\n",&pai1);

    bool ans = !element_cmp(&pai1, &pai3);
    element_clear(&pai1);
    element_clear(&pai2);
    element_clear(&pai3);
    element_clear(&tt);

    return ans;
}

void Accumulator::NonMemWithUpOnAdd(element_s* x, std::pair<element_s*, element_s*> *witness, element_s* y, params pp, element_s* delta){
    element_s temp;
    element_init_Zr(&temp, pp.e);
    //element_init_Zr(&temp2, &pp.e);


    element_sub(&temp, x, y);
    element_mul(witness->second, witness->second, &temp);

    element_s t1, t2;
    element_init_G1(&t1, pp.e);
    element_init_G1(&t2, pp.e);
    element_mul_zn(witness->first, witness->first, &temp);
    element_add(witness->first, witness->first, delta);

    element_clear(&t1);
    element_clear(&t2);
    element_clear(&temp);

 }

void Accumulator::NonMemWithUpOnDelete(element_s* x, std::pair<element_s*, element_s*> *witness, element_s* y, params pp, element_s* delta){
    
    element_s temp,temp2;
    element_init_Zr(&temp, pp.e);
    element_init_Zr(&temp2, pp.e);


    element_sub(&temp, x, y);
    element_invert(&temp2, &temp);
    element_mul(witness->second, witness->second, &temp2);

    element_sub(witness->first, witness->first, delta);
    element_mul_zn(witness->first, witness->first, &temp2);

    
    element_clear(&temp);
    element_clear(&temp2);
    

}

ZKP* Accumulator::ConstructZkpOfWitness(params pp, element_s* y, std::pair<element_s*, element_s* > *witness,element_s* delta, element_s* vk,
                                        std::tuple<element_s*, element_s*, element_s*, element_s*> *proof_params){

    
    element_s t1,t3,t4,d3,d4, A2, B1, B2, CI;
    element_init_Zr(&t1, pp.e);
    element_init_Zr(&t3, pp.e);
    element_init_Zr(&t4, pp.e);
    element_init_Zr(&d3, pp.e);
    element_init_Zr(&d4, pp.e);
    element_random(&t1);
    element_random(&t3);
    element_random(&t4);


    element_s rr,rt1,rt3,rt4,rd3,rd4, neg_rd3, neg_rd4;

    element_init_Zr(&rr, pp.e);
    element_init_Zr(&rt1, pp.e);
    element_init_Zr(&rt3, pp.e);
    element_init_Zr(&rt4, pp.e);
    element_init_Zr(&rd3, pp.e);
    element_init_Zr(&rd4, pp.e);
    element_init_Zr(&neg_rd3, pp.e);
    element_init_Zr(&neg_rd4, pp.e);
    element_random(&rr);
    element_random(&rt1);
    element_random(&rt3);
    element_random(&rt4);
    element_random(&rd3);
    element_random(&rd4);
    element_neg(&neg_rd3, &rd3);
    element_neg(&neg_rd4, &rd4);


    element_s A_bar, neg_wit;
    element_init_G2(&A_bar, pp.e);
    element_mul_zn(&A_bar, pp.G_bar, witness->second);

    element_init_G2(&A2, pp.e);
    element_init_G1(&B1, pp.e);
    element_init_G1(&B2, pp.e);
    element_init_G2(&CI, pp.e);

    // creating CI
    element_s r, temp;
    element_init_Zr(&r, pp.e);
    
    element_init_G2(&temp, pp.e);
    element_random(&r);
    element_mul_zn(&d3, &t3,&r);
    element_mul_zn(&d4, &t4,&r);
    element_mul_zn(&CI, std::get<2>(*proof_params), &r);
    element_mul_zn(&temp, pp.G_bar, y);
    element_add(&temp, &temp,vk);
    element_add(&CI,&CI, &temp);

    // creating A2
    element_mul_zn(&temp, std::get<3>(*proof_params), &t1);
    element_add(&A2, &A_bar, &temp);

    // creating B1
    element_init_G1(&temp, pp.e);
    element_mul_zn(&temp, std::get<0>(*proof_params), &t3);
    element_set(&B1, &temp);
    element_mul_zn(&temp, std::get<1>(*proof_params), &t4);
    element_add(&B1, &B1, &temp);

    //creating B2
    element_mul_zn(&temp, std::get<1>(*proof_params), &t3);
    element_add(&B2, witness->first, &temp);

    element_s R21, R22, R3;
    element_init_G1(&R21, pp.e);
    element_init_G1(&R22, pp.e);
    element_init_GT(&R3, pp.e);

    // creating R21
    element_mul_zn(&temp, std::get<0>(*proof_params),&rt3);
    element_set(&R21, &temp);
    element_mul_zn(&temp, std::get<1>(*proof_params),&rt4);
    element_add(&R21, &R21, &temp);

    // creating R22
    element_mul_zn(&R22, &B1, &rr);
    element_mul_zn(&temp, std::get<0>(*proof_params), &neg_rd3);
    element_add(&R22, &R22,&temp);
    element_mul_zn(&temp, std::get<1>(*proof_params), &neg_rd4);
    element_add(&R22, &R22,&temp);

    // creating R3
    element_s pai1,pai2, pai3, pai4, challenge, sr, st1, st3, st4, sd3, sd4;

    element_init_GT(&pai1,pp.e);
    element_init_GT(&pai2,pp.e);
    element_init_GT(&pai3,pp.e);
    element_init_GT(&pai4,pp.e);

    pairing_apply(&pai1,delta,std::get<3>(*proof_params),pp.e);
    element_mul_zn(&pai1, &pai1, &rt1);
    
    pairing_apply(&pai2,std::get<1>(*proof_params),&CI,pp.e);
    element_mul_zn(&pai2, &pai2, &rt3);

    pairing_apply(&pai3,std::get<1>(*proof_params),std::get<2>(*proof_params),pp.e);
    element_mul_zn(&pai3, &pai3, &neg_rd3);

    pairing_apply(&pai4,&B2,std::get<2>(*proof_params),pp.e);
    element_mul_zn(&pai4, &pai4, &rr);

    element_mul(&R3, &pai1, &pai2);
    element_mul(&R3, &R3, &pai3);
    element_mul(&R3, &R3, &pai4);

    element_printf("R21 = %B\n\n",&R21);
    element_printf("R22 = %B\n\n",&R22);
    element_printf("R3 = %B\n\n",&R3);

    element_init_Zr(&challenge, pp.e);
    element_init_Zr(&sr, pp.e);
    element_init_Zr(&st1, pp.e);
    element_init_Zr(&st3, pp.e);
    element_init_Zr(&st4, pp.e);
    element_init_Zr(&sd3, pp.e);
    element_init_Zr(&sd4, pp.e);

    std::pair<unsigned char*, int> hash = convert_to_byte(proof_params, &A2,&B1,&B2,&CI, &R21,&R22,&R3);

    //print_text(hash.first, hash.second);
    element_from_hash(&challenge, hash.first, hash.second);
    delete [] hash.first;

    element_printf("challenge = %B\n\n",&challenge);

    element_init_Zr(&temp, pp.e);
    element_mul(&temp, &challenge, &r);
    element_add(&sr, &rr, &temp);

    element_mul(&temp, &challenge, &t1);
    element_add(&st1, &rt1, &temp);

    element_mul(&temp, &challenge, &t3);
    element_add(&st3, &rt3, &temp);

    element_mul(&temp, &challenge, &t4);
    element_add(&st4, &rt4, &temp);

    element_mul(&temp, &challenge, &d3);
    element_add(&sd3, &rd3, &temp);

    element_mul(&temp, &challenge, &d4);
    element_add(&sd4, &rd4, &temp);
    element_printf("A22 = %B\n", &A2);

    ZKP* s = new ZKP(&A2,&B1, &B2, &CI, &challenge, &sr, &st1, &st3, &st4, &sd3, &sd4, pp);
    return s;
}

std::pair<unsigned char*, int> Accumulator::convert_to_byte( std::tuple<element_s*, element_s*, element_s*, element_s*> *proof, element_s* A2, element_s* B1,element_s* B2,element_s* CI,element_s* R21, element_s* R22, element_s* R3){

    int size_g = element_length_in_bytes(std::get<1>(*proof));
    unsigned char byte_g[size_g]; element_to_bytes(byte_g,std::get<1>(*proof));

    //print_text(byte_g, size_g);

    int size_h2 = element_length_in_bytes(std::get<2>(*proof));
    unsigned char byte_h2[size_h2]; element_to_bytes(byte_h2,std::get<2>(*proof));

   // print_text(byte_h2, size_h2);

    int size_h = element_length_in_bytes(std::get<3>(*proof));
    unsigned char byte_h[size_h]; element_to_bytes(byte_h,std::get<3>(*proof));

    //print_text(byte_h, size_h);
    
    //print_text(byte_u,size_u);
    int size_A2 = element_length_in_bytes(A2);
    unsigned char byte_A2[size_A2]; element_to_bytes(byte_A2,A2);

    //print_text(byte_A2, size_A2);

    int size_B1 = element_length_in_bytes(B1);
    unsigned char byte_B1[size_B1]; element_to_bytes(byte_B1,B1);

    //print_text(byte_B1, size_B1);

    int size_B2 = element_length_in_bytes(B2);
    unsigned char byte_B2[size_B2]; element_to_bytes(byte_B2,B2);
    //print_text(byte_B2, size_B2);

    int size_CI = element_length_in_bytes(CI);
    unsigned char byte_CI[size_CI]; element_to_bytes(byte_CI,CI);

    //print_text(byte_CI, size_CI);

    //print_text(byte_epoch,size_epoch);

    int size_R21 = element_length_in_bytes(R21);
    unsigned char byte_R21[size_R21]; element_to_bytes(byte_R21,R21);
    //print_text(byte_R21, size_R21);
    //print_text(byte_msg1,size_msg1);

    int size_R22 = element_length_in_bytes(R22);
    unsigned char byte_R22[size_R22]; element_to_bytes(byte_R22,R22);

    //print_text(byte_R22, size_R22);
    int size_R3 = element_length_in_bytes(R3);
    unsigned char byte_R3[size_R3]; element_to_bytes(byte_R3,R3);

   // print_text(byte_R3, size_R3);
    int total_size = size_g + size_h2 + size_h + size_A2 + size_B1 + size_B2 + size_CI + size_R21 + size_R22 + size_R3;
    unsigned char* final_arr = new unsigned char[total_size];

    bzero(final_arr,total_size);
    memcpy(final_arr,byte_g,size_g);
    memcpy(final_arr+size_g,byte_h2,size_h2);memcpy(final_arr+size_g + size_h2,byte_h,size_h);
    memcpy(final_arr+size_g + size_h2 + size_h ,byte_A2,size_A2);memcpy(final_arr+size_g + size_h2 + size_h + size_A2,byte_B1,size_B1);
    memcpy(final_arr+size_g + size_h2 + size_h + size_A2 + size_B1,byte_B2,size_B2);memcpy(final_arr+size_g + size_h2 + size_h + size_A2 + size_B1 + size_B2,byte_CI,size_CI);
    memcpy(final_arr+size_g + size_h2 + size_h + size_A2 + size_B1 + size_B2 + size_CI, byte_R21,size_R21);
    memcpy(final_arr+size_g + size_h2 + size_h + size_A2 + size_B1 + size_B2 + size_CI + size_R21,byte_R22, size_R22);
    memcpy(final_arr+size_g + size_h2 + size_h + size_A2 + size_B1 + size_B2 + size_CI + size_R21 + size_R22,byte_R3, size_R3);
    

   // print_text(final_arr, total_size);
    
    //print_text(final_arr,total_size);

    std::cout<<"Over here"<<std::endl;
    return std::make_pair(final_arr, total_size);
}

bool Accumulator::VerifyZKP(params pp,std::tuple<element_s*, element_s*, element_s*, element_s*, element_s*, element_s*, element_s*, element_s*, element_s*,element_s*, element_s*> *proof, 
                            std::tuple<element_s*, element_s*, element_s*, element_s*> *proof_params, element_s* delta){
                            
        element_s A2, B1,B2,CI, c, sr, st1, st3, st4, sd3, sd4, neg_c, neg_sd3, neg_sd4;
        element_init_G2(&A2, pp.e);
        element_init_G1(&B1, pp.e);
        element_init_G1(&B2, pp.e);
        element_init_G2(&CI, pp.e);
        element_init_Zr(&c, pp.e);
        element_init_Zr(&neg_c, pp.e);
        element_init_Zr(&sr, pp.e);
        element_init_Zr(&st1, pp.e);
        element_init_Zr(&st3, pp.e);
        element_init_Zr(&st4, pp.e);
        element_init_Zr(&sd3, pp.e);
        element_init_Zr(&sd4, pp.e);
        element_init_Zr(&neg_sd3, pp.e);
         element_init_Zr(&neg_sd4, pp.e);

        element_set(&A2, std::get<0>(*proof));
        element_set(&B1, std::get<1>(*proof));
        element_set(&B2, std::get<2>(*proof));
        element_set(&CI, std::get<3>(*proof));
        element_set(&c, std::get<4>(*proof));
        element_neg(&neg_c,&c);
        element_set(&sr, std::get<5>(*proof));
        element_set(&st1, std::get<6>(*proof));
        element_set(&st3, std::get<7>(*proof));
        element_set(&st4, std::get<8>(*proof));
        element_set(&sd3, std::get<9>(*proof));
        element_set(&sd4, std::get<10>(*proof));
        element_neg(&neg_sd3, &sd3);
        element_neg(&neg_sd4, &sd4);
        element_s R21, R22,R3, temp;
        element_init_G1(&R21, pp.e);
        element_init_G1(&temp, pp.e);
        element_init_G1(&R22, pp.e);
        element_init_GT(&R3, pp.e);

        // calculating R21
        element_mul_zn(&R21, std::get<1>(*proof_params), &st4);
        element_mul_zn(&temp, std::get<0>(*proof_params), &st3);
        element_add(&R21, &R21, &temp);
        element_mul_zn(&temp, &B1, &neg_c);
        element_add(&R21, &R21, &temp);

        // calculating R22
        element_mul_zn(&R22, std::get<1>(*proof_params), &neg_sd4);
        element_mul_zn(&temp, std::get<0>(*proof_params), &neg_sd3);
        element_add(&R22, &R22, &temp);
        element_mul_zn(&temp, &B1, &sr);
        element_add(&R22, &R22, &temp);

        // calculating R3
        element_s pai1, pai2, pai3, pai4, pai5, pai6, pai7, pai8;

        element_init_GT(&pai1,pp.e);
        element_init_GT(&pai2,pp.e);
        element_init_GT(&pai3,pp.e);
        element_init_GT(&pai4,pp.e);
        element_init_GT(&pai5,pp.e);
        element_init_GT(&pai6,pp.e);
        element_init_GT(&pai7,pp.e);
        element_init_GT(&pai8,pp.e);

        pairing_apply(&pai1,delta,std::get<3>(*proof_params),pp.e);
        element_mul_zn(&pai1, &pai1, &st1);

        pairing_apply(&pai2,std::get<1>(*proof_params),&CI,pp.e);
        element_mul_zn(&pai2, &pai2, &st3);

        pairing_apply(&pai3,std::get<1>(*proof_params),std::get<2>(*proof_params),pp.e);
        element_mul_zn(&pai3, &pai3, &neg_sd3);

        pairing_apply(&pai4,&B2,std::get<2>(*proof_params),pp.e);
        element_mul_zn(&pai4, &pai4, &sr);

        pairing_apply(&pai5,std::get<0>(*proof_params),pp.G_bar,pp.e);
        //element_mul_zn(&pai5, &pai5, &c);


        pairing_apply(&pai6,delta,&A2,pp.e);
        //element_mul_zn(&pai6, &pai6, &neg_c);

        pairing_apply(&pai7,&B2,&CI,pp.e);
        //element_mul_zn(&pai7, &pai7, &neg_c);
        element_mul(&pai8, &pai6, &pai7);
        element_div(&pai8, &pai8, &pai5);
        element_mul_zn(&pai8, &pai8, &c);

        element_mul(&R3, &pai1, &pai2);
        element_mul(&R3, &R3, &pai3);
        element_mul(&R3, &R3, &pai4);
        element_div(&R3, &R3, &pai8);

        element_s c_dash;
        element_init_Zr(&c_dash, pp.e);
        std::cout<<"INvecrify"<<std::endl;
        element_printf("R21 = %B\n\n",&R21);
        element_printf("R22 = %B\n\n",&R22);
        element_printf("R3 = %B\n\n",&R3);
        std::pair<unsigned char*, int> hash = convert_to_byte(proof_params, &A2,&B1,&B2,&CI, &R21,&R22,&R3);

        element_from_hash(&c_dash, hash.first, hash.second);
        delete [] hash.first;

        element_printf("challenge = %B\n\n",&c_dash);

        return !element_cmp(&c_dash, &c);

}
