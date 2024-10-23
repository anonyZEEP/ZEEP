#include "Issuer.h"
#include "Vehicle.h"
#include "PS_Commit.h"
#include "Symmetric_enc.h"
#include<cstdlib>
#include <bits/stdc++.h>
#include <chrono>
using namespace std::chrono;

// using namespace CryptoPP;
// using byte = unsigned char ;


// void init_arr(std::vector<element_s> *arr, int size, params p){
//     for(int i=0;i<size;i++){
//         element_s* temp = (element_s*)malloc(sizeof(*(temp)));
//         arr->push_back(temp);
//         element_init_Zr(&arr->at(i), p.e);
//     }
// }
// void init_arr2(std::vector<element_s> *arr, int size, params p){
//     for(int i=0;i<size;i++){
//         element_init_G2(&arr->at(i), p.e);
//     }
// }
// void init_keys(std::vector<element_s> *vk,std::vector<element_s> *sk, int atrributes, params p){
//     for(int i=0;i<atrributes;i++){
//         element_init_Zr(&sk->at(i), p.e);
//         // element_random(&t);
//         // element_random(&a);
//     }
//     for(int i=0;i<atrributes+1;i++){
//         element_init_G2(&vk->at(i), p.e);
//         // element_random(&t);
//         // element_random(&a);
//     }
// }
// void print_text2(byte text[],int size){
//     std::string encoded;

//     encoded.clear();
// 	StringSource(text, size, true,
// 		new HexEncoder(
// 			new StringSink(encoded)
// 		) // HexEncoder
// 	); // StringSource
// 	std::cout << "Hexcoded: " << encoded << std::endl;
// }

// void init_pk(std::vector<element_s*> *arr, int size, params p){
    
//     for(int i=0;i<2*size + 3;i++) {
//         struct element_s* t = (element_s *)malloc(sizeof(element_s));
//         (*arr).push_back(t);
//     }
//     element_init_G1(arr->at(0), p.e);
//     element_init_G2(arr->at(1), p.e);
//     int count = 2;
//     for(int i=0;i<size;i++){
//         element_init_G1(arr->at(count), p.e);
//         count++;
//     }
//     for(int i=0;i<size+1;i++){
//         element_init_G2(arr->at(count), p.e);
//         count++;
//     }
// }

// class token{

//     public:
//     element_s sig;
//     element_s b;
//     element_s c;
//     int size;
//     token(params pp){

//         element_init_G1(&a, &pp.e);
//         element_init_G1(&b, &pp.e);
//         element_init_G1(&c, &pp.e);
//         int a,b,c
//     }
// };
// class pk{

// };
// class sk{

// };

// class msg{
//     element_s zone_num;
//     element_s epoch;
//     std::pair<element_s, byte*> ek;
//     int size;
//     msg(params pp){
//         element_init_Zr(&zone_num, &pp.e);
//         element_init_Zr(&epoch, &pp.e);
//         element_init_G1(&ek.first, &pp.e);
//         ek.second = new byte[AES::DEFAULT_KEYLENGTH];
//         size = element_length_in_bytes(&zone_num) + 
//                element_length_in_bytes(&epoch) + 
//                element_length_in_bytes(&ek.first) + AES::DEFAULT_KEYLENGTH;
//     }
//     ~msg(){
//         delete [] ek.second;
//     }
// };
int main(){

    Issuer is;
    is.Setup(3, 10);

    Vehicle a;
    a.Setup(&is);

    auto start = high_resolution_clock::now();
    std::pair<element_s*, std::tuple<element_s*, element_s*, element_s*>> p = a.Registration();

    std::tuple<std::pair<element_s*, element_s*>, std::pair<element_s*, element_s*>> k = is.Register_User(p);
    auto end = high_resolution_clock::now();
    std::cout<<"Registration time = "<< duration_cast<microseconds>(end - start).count()<<std::endl;

    auto st = high_resolution_clock::now();
    std::cout<<a.Verify_Registration(k)<<std::endl;
    auto end2 = high_resolution_clock::now();
    std::cout<<"Verification time = "<< duration_cast<microseconds>(end2- st).count()<<std::endl;

    st = high_resolution_clock::now();
    std::tuple<std::tuple<element_s*,element_s*, element_s*,std::vector<element_s*>>, element_s*,element_s*, element_s*,element_s*,element_s*, 
std::vector<ZKP*>> tok = a.Auth_to_DGSA();
    end2 = high_resolution_clock::now();
    std::cout<<"Authentication time = "<< duration_cast<microseconds>(end2- st).count()<<std::endl;

    st = high_resolution_clock::now();
    std::tuple<std::pair<element_s*, element_s*>, std::pair<element_s*, element_s*>, std::vector<element_s*>> tok2 = is.Autheticate_User(tok);
    end2 = high_resolution_clock::now();
    std::cout<<"Auth Verification time = "<< duration_cast<microseconds>(end2- st).count()<<std::endl;
    
    Symmetric_enc en;
    std::pair<byte *, byte*> key = en.KeyGen(32, 16);

    st = high_resolution_clock::now();
    std::string msg = "Some message";
    std::pair<byte*, size_t> encrypt = en.Encrypt_payload(key.first, key.second,msg);
    end = high_resolution_clock::now();
    std::cout<<"Encrypt = "<< duration_cast<microseconds>(end- st).count()<<std::endl;

    std::string cipher;
    st = high_resolution_clock::now();
    std::pair<byte*, size_t> decrypt = en.Encrypt_payload(key.first, key.second,cipher);
    end = high_resolution_clock::now();
    std::cout<<"Decrypt = "<< duration_cast<microseconds>(end- st).count()<<std::endl;

    


    //ac.getWitness(&temp,&temp,is.p);
    
    // ac.Add(&sk, is.p, &x, &delta);
    // std::pair<element_s*, element_s*> pa = std::make_pair(&w1, &w2);
    // ac.NonMemWithCreate(&sk, is.p, &y,&wl, &pa);


















    // PSCommit ps;
    // params p = ps.Setup();

    // element_s sk;
    // element_init_G1(&sk, p.e);
    // std::vector<element_s*> vk;
      
    // init_pk(&vk, 3, p);
    // //printf("Address of vk is %p\n", (void *)vk.at(0));
    // ps.KeyGen(3, p, &sk, &vk);
    // std::vector<element_s*> msg;
    // for(int i=0;i<2;i++){
    //     element_s* a = (element_s*)malloc(sizeof(*a));
    //     element_init_Zr(a, p.e);
    //     element_random(a);
    //     element_printf("msg = %B", a);
    //     msg.push_back(a);
    // }
    // std::pair<element_s*, element_s*> ty = ps.GenCommitment(&msg, &vk, p);

    // element_printf("r = %B\n", ty.first);
    // element_printf("C = %B\n", ty.second);

    // element_s* ep = (element_s*)malloc(sizeof(*ep));
    // element_init_Zr(ep, p.e);
    // element_random(ep);
    // element_printf("epoch = %B\n", ep);

    // std::pair<element_s*, element_s*> signn = ps.Sign(ty.second, &sk, ep, &vk, p);
    
    // ps.Unblind(signn, ty.first, p);

    // element_printf("signn second = %B\n", signn.second);

    // std::cout<<ps.Verify(signn, msg, ep,vk, p)<<std::endl;



    // char ans[1000];
    // // element_snprint(ans,sizeof(ans),&k.first);
    // // std::cout<<"s_k "<<std::string(ans)<<std::endl;

    // // for(int i=0;i<k.second.size();i++){
    // //      element_snprint(ans,sizeof(ans),&k.second.at(i));
    // // std::cout<<"p_k "<<std::string(ans)<<std::endl;
    // // }
    // std::vector<element_s> msg;

    // for(int i=0;i<2;i++){
    //     element_s t;
    //     element_init_Zr(&t, &p.e);
    //     element_random(&t);
    //     element_snprint(ans,sizeof(ans),&t);
    //     std::cout<<"msg "<<std::string(ans)<<std::endl;
    //     //element_mul_zn(&t, &g, &temp.at(i+1));
    //     msg.push_back(t);
    // }
    // std::pair<element_s, element_s> k2 = ps.GenCommitment(msg,k.second, p);
    // element_s C = k2.second;
    // element_s k2r = k2.first;

    // element_s t;
    // element_init_Zr(&t, &p.e);
    // element_random(&t);
    // element_snprint(ans,sizeof(ans),&t);
    // std::cout<<"t "<<std::string(ans)<<std::endl;
    // std::pair<element_s, element_s> sign = ps.Sign(C,k.first,t, k.second,p);
    // std::pair<element_s, element_s> sign2 = ps.Unblind(sign, k2r,p);

    // // element_s a,b,c,d;
    // // element_init_G1(&a, &p.e);
    // // element_init_G1(&b, &p.e);
    // // element_init_G1(&c, &p.e);
    // // element_init_G1(&d, &p.e);

    // // element_mul_zn(&a,&k.second.at(2),&msg.at(0));
    // // // element_mul_zn(&b,&k.second.at(3),&msg.at(1));
    // // element_mul_zn(&c,&k.second.at(3),&t);
    // // element_add(&d, &a,&b);
    // // element_add(&d, &d,&c);
    // // element_add(&d, &d,&k.first);
    // // element_mul_zn(&d,&d, &ps.urr);

    // // element_snprint(ans,sizeof(ans),&d);
    // // std::cout<<"dd "<<std::string(ans)<<std::endl;

    // // element_snprint(ans,sizeof(ans),&sign2.second);
    // // std::cout<<"dd "<<std::string(ans)<<std::endl;


    // //element_s sig2 = sign.second;



    // std::cout<<ps.Verify(sign2,msg,t, k.second,p)<<std::endl;

    // PSCommit ps;
    // params pp = ps.Setup();
    // Accumulator acc;
    // element_s* sk = (element_s*)malloc(sizeof(*sk));
    // element_s* vk = (element_s*)malloc(sizeof(*vk));
    // acc.KeyGen(pp, vk, sk);

    // element_printf("keyss = %B\n\n",sk);
    // element_printf("keyss = %B\n\n",vk);

    // element_s* delta = (element_s*)malloc(sizeof(*delta));
    // element_init_G1(delta, pp.e);
    // element_set(delta, pp.G);

    // element_s* x = (element_s*)malloc(sizeof(*x));
    // element_init_Zr(x, pp.e);
    // element_random(x);

    // element_s* x2 = (element_s*)malloc(sizeof(*x));
    // element_init_Zr(x2, pp.e);
    // element_random(x2);

    // element_s* x3 = (element_s*)malloc(sizeof(*x));
    // element_init_Zr(x3, pp.e);
    // element_random(x3);


    // std::vector<element_s*> wl;
    // wl.push_back(x);

    // element_s* y = (element_s*)malloc(sizeof(*y));
    // element_init_Zr(y, pp.e);
    // element_random(y);

    // element_s* y_bar = (element_s*)malloc(sizeof(*y));
    // element_init_Zr(y_bar, pp.e);
    // element_set(y_bar, y);

    // element_printf("x = %B\n\n",x);
    // element_printf("delta = %B\n\n",delta);

    // acc.Add(sk,pp, x, delta);

    // element_printf("delta = %B\n\n",delta);


    // std::pair<element_s*, element_s*> witness;
    // witness.first = (element_s*)malloc(sizeof(*witness.first));
    // witness.second = (element_s*)malloc(sizeof(*witness.second));

    // // std::pair<element_s*, element_s*> witness2;
    // // witness2.first = (element_s*)malloc(sizeof(*witness.first));
    // // witness2.second = (element_s*)malloc(sizeof(*witness.second));

    // acc.NonMemWithCreate(sk,pp,y,&wl,&witness);
    // element_printf("witness = %B\n\n",witness.first);
    // element_printf("witness = %B\n\n",witness.second);

    // std::cout<<acc.VerNonMem(pp,y,&witness, vk, delta)<<std::endl;

    // element_s* p1 = (element_s*)malloc(sizeof(*p1));
    // element_init_G1(p1, pp.e);
    // element_set(p1, delta);

    // acc.Add(sk,pp, x2, delta);
    // wl.push_back(x2);

    // element_s* p2 = (element_s*)malloc(sizeof(*p1));
    // element_init_G1(p2, pp.e);
    // element_set(p2, delta);
    // //acc.NonMemWithCreate(sk, pp, y_bar, &wl, &witness2);

    // // element_printf("witness2 = %B\n\n",witness2.first);
    // // element_printf("witness2 = %B\n\n",witness2.second);

    // acc.NonMemWithUpOnAdd(x2,&witness, y,pp, p1);

    // element_printf("witness = %B\n\n",witness.first);
    // element_printf("witness = %B\n\n",witness.second);

    // std::cout<<acc.VerNonMem(pp,y,&witness, vk, delta)<<std::endl;

    // element_printf("delta before = %B\n\n",delta);
    // acc.Delete(sk, pp, x2, delta);
    // element_printf("delta aftre = %B\n\n",delta);

    // acc.NonMemWithUpOnDelete(x2,&witness, y, pp, delta);

    // element_printf("witness = %B\n\n",witness.first);
    // element_printf("witness = %B\n\n",witness.second);


    // std::cout<<acc.VerNonMem(pp,y,&witness, vk, delta)<<std::endl;

    // element_s* g = (element_s*) malloc(sizeof(*g));
    // element_s* h2 = (element_s*) malloc(sizeof(*h2));
    // element_s* h = (element_s*) malloc(sizeof(*h));
    // element_init_G1(g, pp.e);
    // element_init_G2(h2, pp.e);
    // element_init_G2(h, pp.e);
    // element_random(g);element_random(h2);element_random(h);

    // //element_printf("G = %B\n\n",pp.G);
    // auto pub_pa = std::make_tuple(pp.G, g,h2,h);
    // std::tuple<element_s*, element_s*, element_s*, element_s*, element_s*, element_s*, element_s*, element_s*, element_s*,element_s*, element_s*> 
    // ans = acc.ConstructZkpOfWitness(pp,y,&witness,delta,vk,&pub_pa);

    // std::cout<<acc.VerifyZKP(pp, &ans,&pub_pa, delta)<<std::endl;


    // element_s a, b,c, pai1, pai2, g111,g22;
    // element_init_Zr(&a, pp.e);
    // element_init_Zr(&b, pp.e);
    // element_init_Zr(&c, pp.e);
    // element_init_GT(&pai1, pp.e);
    // element_init_GT(&pai2, pp.e);
    // element_init_G1(&g111, pp.e);
    // element_init_G2(&g22, pp.e);
    // element_random(&a);
    // element_random(&b);
    // element_mul(&c, &b, &a);
    // element_mul_zn(&g111, pp.G,&a);
    // element_mul_zn(&g22, pp.G_bar,&b);

    // pairing_apply(&pai1, &g111,&g22, pp.e);
    // element_mul_zn(&g22, pp.G_bar,&c);
    // pairing_apply(&pai2, pp.G,&g22, pp.e);

    // std::cout<< element_cmp(&pai1, &pai2) <<std::endl;


    



    // char ans[1000];
    // // element_snprint(ans,sizeof(ans),&keys.first);
    // // std::cout<<"first "<<std::string(ans)<<std::endl;

    // element_printf(" first %B\n", &keys.first);
    // // element_snprint(ans,sizeof(ans),&keys.second);
    // // std::cout<<"g "<<std::string(ans)<<std::endl;
    // element_printf("second %B\n", &keys.second);
    // element_s x;
    // element_init_Zr(&x, &pp.e);
    // element_random(&x);

    // element_printf("x =  %B\n", &x);
    // // element_snprint(ans,sizeof(ans),&x);
    // // std::cout<<"x "<<std::string(ans)<<std::endl;

    // element_s accum_val = acc.Add(keys.first, pp, x,pp.G);

    // element_printf("accum_val =  %B\n", &accum_val);
    // // element_snprint(ans,sizeof(ans),&accum_val);
    // // std::cout<<"accum_val "<<std::string(ans)<<std::endl;

    // // accum_val = acc.Delete(keys.first, pp, x,accum_val);
    // // element_snprint(ans,sizeof(ans),&accum_val);
    // // std::cout<<"accum_val "<<std::string(ans)<<std::endl;

    // element_s p;
    // element_init_Zr(&p, &pp.e);
    // element_random(&p);
    // element_printf("p =  %B\n", &p);
    // // element_snprint(ans,sizeof(ans),&p);
    // // std::cout<<"x1 =  "<<std::string(ans)<<std::endl;
    // std::vector<element_s> wl;
    // wl.push_back(x);
    // std::pair<element_s, element_s> witness = acc.NonMemWithCreate(keys.first,pp,p,wl);
    // element_s t;
    // element_init_Zr(&t, &pp.e);
    // element_set(&t, &witness.second);
    // element_printf("c =  %B\n", &witness.first);
    // element_snprint(ans,sizeof(ans),&witness.first);
    // std::cout<<"c = "<<std::string(ans)<<std::endl;
    // // element_set0(&p);
    // // element_snprint(ans,sizeof(ans),&p);
    // //     std::cout<<"p "<<std::string(ans)<<std::endl;
    // element_printf("d =  %B\n", &t);
    // element_snprint(ans,sizeof(ans),&t);
    // std::cout<<"d = "<<std::string(ans)<<std::endl;
    // DGSA dg;
    // char s[1024];
    // PS_Sign si;
    
    // std::vector<element_s> sk(4);
    
    // //init_arr(&sk,4,p);
    // std::vector<element_s> pk(5);

    // init_keys(&pk, &sk, 4,p);
    
    // //init_arr2(&pk,5,p);
    // std::vector<element_s> signat;
    // element_s a,b,c;
    // element_init_Zr(&a, &p.e);
    // element_init_G1(&b, &p.e);
    // element_init_G1(&c, &p.e);
    // signat.push_back(a);signat.push_back(b);signat.push_back(c);
    // si.KeyGen(p, 2, &pk, &sk);
    
    
    // // element_printf("keyss = %B\n\n",&(sk[0]));
    // // element_printf("keys = %B\n\n",&(sk[1]));
    // // element_printf("keys = %B\n\n",&(sk[2]));
    // // element_printf("keys = %B\n\n",&(sk[3]));
    // // element_printf("keys = %B\n\n",&(pk.at(0)));
    // // element_printf("keys = %B\n\n",&(pk.at(1)));
    // // element_printf("keys = %B\n\n",&(pk.at(2)));
    // // element_printf("keys = %B\n\n",&(pk.at(3)));
    // // element_printf("keys = %B\n\n",&(pk.at(4)));

    // //element_printf("keys = %B\n\n",&keys.second.at(2));
    // std::vector<element_s> msg;

    // for(int i=0;i<2;i++){
    //     element_s t;
    //     element_init_Zr(&t, &p.e);
    //     element_random(&t);
    //     // element_snprint(ans,sizeof(ans),&t);
    //     // std::cout<<"msg "<<std::string(ans)<<std::endl;
    //     //element_mul_zn(&t, &g, &temp.at(i+1));
    //     msg.push_back(t);
    // }
    // element_printf("msg = %B\n\n",&(msg.at(0)));
    // element_printf("msg = %B\n\n",&(msg.at(1)));
    
    // si.Sign(p,&sk, &msg, &signat);
    // element_printf("signat = %B\n\n",&(signat.at(0)));
    // element_printf("signat = %B\n\n",&(signat.at(1)));
    // element_printf("signat = %B\n\n",&(signat.at(2)));

    
    // std::cout<<si.Verify(p,&pk, &msg, &signat)<<std::endl;

    
	// prng.GenerateBlock(Kp, sizeof(Kp));
    // print_text2(Kp,AES::DEFAULT_KEYLENGTH);

    // ElGammal el;
    // element_s e_sk, e_pk;
    // el.KeyGen(&e_sk, &e_pk);
    // element_printf("msg = %B\n\n",&e_sk);
    // element_printf("msg = %B\n\n",&e_pk);
    // std::pair<element_s, byte*> el_message;
    // element_init_G1(&el_message.first,&p.e);
    // element_set(&el_message.first, &e_pk);
    // AutoSeededRandomPool prng;
    // el_message.second = new byte[AES::DEFAULT_KEYLENGTH];
    // //print_text2(el_message.second, AES::DEFAULT_KEYLENGTH);
	// prng.GenerateBlock(el_message.second, AES::DEFAULT_KEYLENGTH);
    // print_text2(el_message.second, AES::DEFAULT_KEYLENGTH);

    


    // el.Encrypt(Kp, &pk, &abc);
    // print_text2(abc.second,AES::DEFAULT_KEYLENGTH);

    // byte ans[AES::DEFAULT_KEYLENGTH];
    // el.Decrypt(&sk, &abc, ans);
    // print_text2(ans, AES::DEFAULT_KEYLENGTH);

    // DGSA dg;
    // PS_Sign pss;
    // std::vector<std::tuple<element_s, element_s, element_s> > st;
    // token tk(p);
    //element_random(&tk.a);
    // element_printf("a = %B\n\n",&tk.a);

    // element_s a,b,c;
    // element_init_Zr(&a,&p.e);
    // element_init_G1(&b,&p.e);
    // element_init_G1(&c,&p.e);


    // element_s id, epoch;
    
    
    // // std::vector<element_s> ps_sk(4);
    // // std::vector<element_s> ps_vk(5);
    // // init_keys(&ps_vk, &ps_sk, 4, p);
    // //pss.KeyGen(pss.pp, 2, &ps_vk, &ps_sk);
    // element_init_Zr(&id, &p.e);
    // element_init_Zr(&epoch, &p.e);
    // element_random(&id);
    // element_random(&epoch);
    // element_printf("id = %B\n\n",&id);
    // element_printf("epoch = %B\n\n",&epoch);
    // element_printf("x_cap = %B\n\n",&(dg.ps_sk.at(0)));
    // dg.Issuer_DGSA(&dg.ps_sk, &st, id, epoch, &signat);
    // std::tuple<element_s, element_s , element_s, element_s, element_s> cred;
    // element_init_Zr(&std::get<0>(cred),&p.e);
    // element_init_Zr(&std::get<1>(cred),&p.e);
    // element_init_Zr(&std::get<2>(cred),&p.e);
    // element_init_G1(&std::get<3>(cred),&p.e);
    // element_init_G1(&std::get<4>(cred),&p.e);

    // dg.Vehicle_DGSA(id,epoch, &dg.ps_vk, &signat, &cred);

    // std::tuple< element_s, element_s, element_s, element_s, element_s> tok;
    
    // element_init_G1(&std::get<0>(tok),&p.e);
    // element_init_G1(&std::get<1>(tok),&p.e);
    // element_init_Zr(&std::get<2>(tok),&p.e);
    // element_init_Zr(&std::get<3>(tok),&p.e);
    // element_init_Zr(&std::get<4>(tok),&p.e);

    // element_s d;
    // element_init_Zr(&d,&p.e);
    // element_random(&d);
    // element_printf("zone_num = %B\n\n",&d);
    // std::tuple<element_s, element_s, std::pair<element_s, byte*> > dgsa_msg = std::make_tuple(d,epoch,el_message);
    
    

    // element_printf("id = %B\n\n",&std::get<0>(cred));
    // element_printf("epoch = %B\n\n",&std::get<1>(cred));
    // element_printf("msg = %B\n\n",&std::get<2>(cred));
    // element_printf("msg = %B\n\n",&std::get<3>(cred));
    // element_printf("msg = %B\n\n",&std::get<4>(cred));

    // dg.Auth(&dg.ps_vk, &cred, &dgsa_msg, &tok, p);

    // element_printf("msg = %B\n\n",&std::get<0>(tok));
    // element_printf("msg = %B\n\n",&std::get<1>(tok));
    // element_printf("msg = %B\n\n",&std::get<2>(tok));
    // element_printf("msg = %B\n\n",&std::get<3>(tok));
    // element_printf("msg = %B\n\n",&std::get<4>(tok));

    // std::cout<<dg.Verify(&dg.ps_vk, &dgsa_msg, epoch, &tok,p)<<std::endl;

    // Symmetric_enc sc;
    // byte* key;
    // byte* iv;
    // std::pair<byte*, byte*> k = sc.KeyGen(AES::DEFAULT_KEYLENGTH, AES::BLOCKSIZE);
    // key = k.first;
    // iv = k.second;
    // print_text2(key, AES::DEFAULT_KEYLENGTH);
    // print_text2(iv, AES::BLOCKSIZE);

    // std::pair<byte*, size_t> cipher;
    // std::string message = "adbcd";
    // cipher = sc.Encrypt_payload(key, iv,message);
    // std::cout<<cipher.second<<"  this is sidf"<<std::endl;
    // print_text2(cipher.first, cipher.second);
    // std::string m(cipher.first, cipher.first + cipher.second);
    
    // std::pair<byte*, size_t> siph = sc.Decrypt_payload(key, iv, m);

    // std::cout<<siph.second<<"  this is sidf"<<std::endl;

    // print_text2(siph.first, siph.second);

    // Issuer is;

    // is.Setup(3);
    // element_printf("msg = %B\n\n",is.psign_pk.at(0));
    // element_printf("msg = %B\n\n",is.psign_pk.at(1));
    // element_printf("msg = %B\n\n",is.pk_c.at(2));
    // element_printf("msg = %B\n\n",is.pk_c.at(3));
    // element_printf("msg = %B\n\n",is.pk_c.at(4));
    // element_printf("msg = %B\n\n",is.pk_c.at(5));
    // element_printf("msg = %B\n\n",is.pk_c.at(6));
    // element_printf("msg = %B\n\n",is.pk_c.at(7));
    // element_printf("msg = %B\n\n",is.pk_c.at(8));
    // element_printf("msg = %B\n\n",is.pk_c.at(9));
    // element_printf("msg = %B\n\n",is.pk_c.at(10));



    // Vehicle v;
    // v.Setup(&is);
    // std::pair<element_s*, std::tuple<element_s*, element_s*, element_s*>> p = v.Registration();

    // element_printf("msgdfsfg = %B\n\n",p.first);
    // element_printf("msgdfsfg = %B\n\n",std::get<0>(p.second));
    // element_printf("msgdfsfg = %B\n\n",std::get<1>(p.second));
    // element_printf("msgdfsfg = %B\n\n",std::get<2>(p.second));

    // is.Register_User(p);



    return 0;
}


