#include "Vehicle.h"

Vehicle::Vehicle(){

}
std::pair<unsigned char*, int> Vehicle::convert_to_byte(element_s* c, element_s* g, element_s* Y3){
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

std::pair<unsigned char*, int> Vehicle::convert_to_byte(element_s* u, element_s* p1, element_s* p2, element_s* sig1, element_s* sig2, element_s* c1, element_s* c2){
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

std::tuple<element_s*, element_s*, element_s*> Vehicle::create_pi_reg(){
    element_s r_d,t3;
    element_init_Zr(&r_d, IA->p.e);
    element_init_Zr(&t3, IA->p.e);
    element_random(&r_d);
    element_random(&t3);
    element_s* sr = (element_s *) malloc(sizeof(*sr));
    element_s* st3 = (element_s *) malloc(sizeof(*st3));
    element_s* challenge = (element_s *) malloc(sizeof(*challenge));
    element_init_Zr(sr, IA->p.e);
    element_init_Zr(st3, IA->p.e);
    element_init_Zr(challenge, IA->p.e);

    element_s u, temp;
    element_init_G1(&u, IA->p.e);
    element_init_G1(&temp, IA->p.e);
    element_mul_zn(&temp, IA->pk_c.at(0), &r_d);
    element_mul_zn(&u,IA->pk_c.at(1 + IA->K), &t3);
    element_add(&u, &u, &temp);
    element_printf("u_veh    = %B\n\n",&u);

    std::pair<unsigned char*, int> cc = convert_to_byte(&u, IA->pk_c.at(0), IA->pk_c.at(1 + IA->K));

    element_from_hash(challenge,cc.first, cc.second);
    
    delete [] cc.first;


    element_s temp2;
    element_init_Zr(&temp2, IA->p.e);
    // element_printf("r = %B \n", new_commit.first);
    // element_printf("t3 = %B \n", ticket_que.at(ticket_que.size()-1));
    element_mul(&temp2, challenge, new_commit.first);
    element_sub(sr, &r_d, &temp2);
    element_mul(&temp2, challenge, ticket_que.at(ticket_que.size()-1));
    element_sub(st3, &t3, &temp2);

    return std::make_tuple(challenge, sr, st3);
    
}
void Vehicle::Setup(Issuer *I){
    this->IA = I;
    for(int i=0;i<IA->K;i++){
        element_s* a = (element_s *) malloc(sizeof(*a));
        element_init_Zr(a, I->p.e);
        if(i != IA->K-1) element_set(a, IA->t_cap);
        ticket_que.push_back(a);
        element_s* b = (element_s *) malloc(sizeof(*b));
        element_init_Zr(b, I->p.e);
        new_ticket_que.push_back(b);
    }
    for(int i=0;i<IA->K-1;i++){
        element_s* a = (element_s *) malloc(sizeof(*a));
        element_init_Zr(a, I->p.e);
        element_s* b = (element_s *) malloc(sizeof(*b));
        element_init_G1(b, I->p.e);
        witness.push_back(std::make_pair(b,a));
    }
    element_s* a = (element_s *) malloc(sizeof(*a));
    element_init_G1(a, I->p.e);
    element_s* b = (element_s *) malloc(sizeof(*b));
    element_init_G1(b, I->p.e);
    sig_on_que = std::make_pair(a,b);
    acc_val = (element_s *) malloc(sizeof(*acc_val));
    element_init_G1(acc_val, I->p.e);
    commit.first = (element_s *) malloc(sizeof(*commit.first));
    commit.second = (element_s *) malloc(sizeof(*commit.second));
    element_init_G1(commit.first, I->p.e);
    element_init_G1(commit.second, I->p.e);
    
}
std::pair<element_s*, std::tuple<element_s*, element_s*, element_s*>> Vehicle::Registration(){
    element_s tk;
    element_init_Zr(&tk, IA->p.e);
    element_random(&tk);
    element_set(ticket_que[IA->K -1], &tk);
    // element_printf("t33    = %B\n\n",ticket_que[IA->K -1]);
    // element_printf("t33    = %B\n\n",ticket_que[IA->K -2]);
    // element_printf("t33    = %B\n\n",ticket_que[IA->K -3]);

    new_commit = IA->pscom.GenCommitment(&ticket_que,&(IA->pk_c), IA->p);
    element_printf("commitment on queue  r = %B    C = %B\n", new_commit.first, new_commit.second);
    std::tuple<element_s*, element_s*, element_s*> ZKP = create_pi_reg();
    element_printf("ZKP = C = %B       sr = %B     st3 = %B\n", std::get<0>(ZKP), std::get<1>(ZKP), std::get<2>(ZKP));
    return std::make_pair(new_commit.second, ZKP);
}

bool Vehicle::Verify_Registration(std::tuple<std::pair<element_s*, element_s*>, std::pair<element_s*, element_s*>> req){

    
    element_set(sig_on_que.first, std::get<0>(req).first);
    element_set(sig_on_que.second, std::get<0>(req).second);
    delete std::get<0>(req).first; delete std::get<0>(req).second;
    // element_printf(" one %B = ", sig_on_que.first);
    // element_printf(" one %B = ", sig_on_que.second);

    IA->pscom.Unblind(sig_on_que,new_commit.first, IA->p);
    
    bool r = IA->pscom.Verify(sig_on_que, ticket_que, IA->epoch, IA->pk_c, IA->p);
    std::cout<<r<<std::endl;
    for(int i=0;i<IA->K-1;i++){
        element_set(witness.at(i).first, std::get<1>(req).first);
        element_set(witness.at(i).second, std::get<1>(req).second);
        bool ans = IA->acc.VerNonMem(IA->p, ticket_que.at(i),&witness.at(i), IA->pk_acc, IA->acc_val);
        std::cout<<ans<<std::endl;
    }
    delete std::get<1>(req).first; delete std::get<1>(req).second;

    element_set(acc_val, IA->acc_val);
    return true;
    
}
std::tuple<element_s*,element_s*, element_s*,std::vector<element_s*>> Vehicle::Create_pi_c(element_s* r_d, element_s* si1, element_s* si2){
    element_s temp1, temp2;
    
    element_init_Zr(&temp1, IA->p.e);
    element_init_G1(&temp2, IA->p.e);

    std::vector<element_s*> t_cap;
    element_s pai1, pai2, u;
    element_init_GT(&pai1, IA->p.e);
    element_init_GT(&pai2, IA->p.e);
    element_init_GT(&u, IA->p.e);
    element_set1(&pai2);
    element_s t1_cap;
    for(int i=0;i<IA->K-1;i++){
        
        element_init_Zr(&t1_cap, IA->p.e);
        element_random(&t1_cap);
        t_cap.push_back(&t1_cap);
        element_mul(&temp1, r_d, &t1_cap);
        element_mul_zn(&temp2, sig_on_que.first, &temp1);
        pairing_apply(&pai1, &temp2, IA->pk_c.at(5 + i + IA->K ), IA->p.e);
        element_mul(&u, &pai1, &pai2);
        element_set(&pai2, &u);
    }


    

    element_s P1, P2, r1_cap, r2_cap, t4_cap;
    element_init_Zr(&r1_cap, IA->p.e);
    element_init_Zr(&r2_cap, IA->p.e);
    element_init_Zr(&t4_cap, IA->p.e);
    element_random(&r1_cap);element_random(&r2_cap);
    element_random(&t4_cap);
    t_cap.push_back(&t4_cap);
    element_init_G1(&P1, IA->p.e);
    element_init_G1(&P2, IA->p.e);

    element_mul_zn(&P1, IA->pk_c.at(0), &r1_cap);
    element_mul_zn(&P2, IA->pk_c.at(0), &r2_cap);
    for(int i=1;i<IA->K-1;i++){
        
        element_mul_zn(&temp2, IA->pk_c.at(i+1), t_cap.at(i-1));
        element_add(&P1, &P1, &temp2);
        element_mul_zn(&temp2, IA->pk_c.at(i+1), t_cap.at(i));
        element_add(&P2, &P2, &temp2);
    }
    
    element_mul_zn(&temp2, IA->pk_c.at(IA->K), t_cap.at(IA->K-2));
    element_add(&P1, &P1, &temp2);
    element_printf("Y1 = %B\n", IA->pk_c.at(IA->pk_c.size()-1));
    element_printf("t1 = %B\n", t_cap.at(t_cap.size()-1));
    element_mul_zn(&temp2, IA->pk_c.at(IA->pk_c.size()-3-IA->K), t_cap.at(t_cap.size()-1));
    element_add(&P2, &P2, &temp2);

    element_s* challenge = (element_s*) malloc(sizeof(*challenge));
    element_s* sr1 = (element_s*) malloc(sizeof(*sr1));
    element_s* sr2 = (element_s*) malloc(sizeof(*sr2));
    element_init_Zr(challenge, IA->p.e);
    element_init_Zr(sr1, IA->p.e);
    element_init_Zr(sr2, IA->p.e);

    std::pair<unsigned char*, int> cc = convert_to_byte(&u, &P1, &P2,si1, si2, new_commit.second, commit.second);

    element_from_hash(challenge,cc.first, cc.second);
    
    delete [] cc.first;
    element_mul(&temp1, challenge, commit.first);
    element_sub(sr1, &r1_cap, &temp1);

    element_mul(&temp1, challenge, new_commit.first);
    element_sub(sr2, &r2_cap, &temp1);

    std::vector<element_s*> t;
    for(int i=0;i<IA->K;i++){
        element_s* st1 = (element_s*) malloc(sizeof(*st1));
        element_init_Zr(st1, IA->p.e);
        element_mul(&temp1, challenge, ticket_que.at(i));
        element_sub(st1, t_cap.at(i), &temp1);
        t.push_back(st1);
    }

    return std::make_tuple(challenge, sr1, sr2, t);
}
std::tuple<std::tuple<element_s*,element_s*, element_s*,std::vector<element_s*>>, element_s*,element_s*, element_s*,element_s*,element_s*, 
std::vector<ZKP*>> 
Vehicle::Auth_to_DGSA(){

    // update witnesses and check non membership
    // TODO update witness

    for(int i=0;i<IA->K-1;i++){
        bool ans = IA->acc.VerNonMem(IA->p,ticket_que.at(i), &witness.at(i),IA->pk_acc, IA->acc_val);
        std::cout<<ans<<std::endl;

        element_set(new_ticket_que.at(i), ticket_que.at(i+1));

    }
    element_set(commit.first, new_commit.first);
    element_set(commit.second, new_commit.second);
    delete new_commit.first;
    delete new_commit.second;

    element_random(new_ticket_que.at(2));

    new_commit = IA->pscom.GenCommitment(&new_ticket_que,&(IA->pk_c), IA->p);

    element_s r_d;
    element_init_Zr(&r_d, IA->p.e);
    element_random(&r_d);

    element_s* si1 = (element_s*) malloc(sizeof(*si1));
    element_s* si2 = (element_s*) malloc(sizeof(*si2));
    element_init_G1(si1, IA->p.e);
    element_init_G1(si2, IA->p.e);

    element_s* c1 = (element_s*) malloc(sizeof(*c1));
    element_s* c2 = (element_s*) malloc(sizeof(*c2));
    element_init_G1(c1, IA->p.e);
    element_init_G1(c2, IA->p.e);

    element_set(c1, commit.second);
    element_set(c2, new_commit.second);

    element_mul_zn(si1, sig_on_que.first, &r_d);
    element_mul_zn(si2, sig_on_que.second, &r_d);
    
    element_s* t3 = (element_s*) malloc(sizeof(*t3));
    element_init_Zr(t3, IA->p.e);
    element_set(t3, ticket_que.at(2));

    std::tuple<element_s*,element_s*, element_s*,std::vector<element_s*>> proof = Create_pi_c(&r_d, si1, si2);

    std::vector<ZKP*> wit;

    for(int i=0;i<IA->K-1;i++){
        ZKP* w_t1 = IA->acc.ConstructZkpOfWitness(IA->p, ticket_que.at(i), &witness.at(i),IA->acc_val, IA->pk_acc,&(IA->proof_params));
        wit.push_back(w_t1);
    }
    return std::make_tuple(proof, c1, c2, si1, si2, t3, wit);
}

void Verify_Auth(std::tuple<std::pair<element_s*, element_s*>, std::pair<element_s*, element_s*>, std::vector<element_s*>> tok){
    
    
}
