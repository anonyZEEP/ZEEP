
#include "ElGammal.h"

using namespace CryptoPP;
using byte = unsigned char;

void inbuilt_xor(byte a[], byte b[], byte c[], int size){

    for(int i=0;i<size;i++){
        c[i] = a[i]^b[i];
    }
}
void print_text(byte text[],int size){
    std::string encoded;

    encoded.clear();
	StringSource(text, size, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	std::cout << "Hexcoded: " << encoded << std::endl;
}

ElGammal::ElGammal(){
    char param[1024];
    FILE *stream = fopen("f.param", "r");
    size_t count = fread(param, 1, 1024, stream);
    if (!count) pbc_die("input error");
    
    pairing_init_set_buf(pp.e, param, count);

    element_init_Zr(pp.p, pp.e);
    element_init_G1(pp.G, pp.e);
    element_init_G2(pp.G_bar, pp.e);
    element_init_GT(pp.G_T, pp.e);
    element_init_G1(&g, pp.e);
    element_random(&g);

    int y = element_set_str(pp.G,"[1, 2]", 10);
    int h = element_set_str(pp.G_bar,"[[10857046999023057135944570762232829481370756359578518086990519993285655852781, 11559732032986387107991004021392285783925812861821192530917403151452391805634], [8495653923123431417604973247489272438418190587263600148770280649306958101930, 4082367875863433681332203403145435568316851327593401208105741076214120093531]]", 10);
    //int n = element_set_str(&)
    std::cout<<y<<" "<< h<<std::endl;

    

}
void ElGammal::KeyGen(element_s *sk, element_s *pk){
    element_init_Zr(sk, pp.e);
    element_init_G1(pk, pp.e);

    element_random(sk);
    element_mul_zn(pk, &g, sk);

}

void ElGammal::Encrypt(byte msg[],element_s *pk,std::pair<element_s, byte*> *enc){
    element_s r, tok1, tok2;
    element_init_Zr(&r, pp.e);
    element_init_G1(&tok1, pp.e);
    element_init_G1(&tok2, pp.e);
    element_random(&r);
    element_mul_zn(&tok1, &g, &r);
    element_mul_zn(&tok2, pk, &r);

    byte hash[AES::DEFAULT_KEYLENGTH];
    // byte cipher[AES::DEFAULT_KEYLENGTH];
    //byte temp[AES::DEFAULT_KEYLENGTH];
    int size_m_1 = element_length_in_bytes(&tok2);
    std::cout<<size_m_1<<std::endl;
    byte byte_m_1[size_m_1]; element_to_bytes(byte_m_1,&tok2);

    memcpy(hash,byte_m_1,AES::DEFAULT_KEYLENGTH);

    inbuilt_xor(msg, hash, (*enc).second, AES::DEFAULT_KEYLENGTH);

   //memcpy(hash+size_m_1,byte_m_1,size_m_1);
    print_text(msg, AES::DEFAULT_KEYLENGTH);
    print_text(hash, AES::DEFAULT_KEYLENGTH);
    print_text((*enc).second, AES::DEFAULT_KEYLENGTH);

    // free(hash);
    // free(byte_m_1);
    //delete &r;


    // element_mul_zn(&tok2, pk, &r);

    // element_add(&tok2, &tok2, &msg);
    (*enc).first = tok1;
    //(*enc).second = cipher;

    // delete &r;
}
void ElGammal::Decrypt(element_s *sk,std::pair<element_s, byte*> *enc, byte* msg){

        element_s temp;
        element_init_G1(&temp, pp.e);
        element_mul_zn(&temp, &(*enc).first, sk);

        byte hash[AES::DEFAULT_KEYLENGTH];

        int size_m_1 = element_length_in_bytes(&temp);
        std::cout<<size_m_1<<std::endl;
        byte byte_m_1[size_m_1]; element_to_bytes(byte_m_1,&temp);
        
        memcpy(hash,byte_m_1,AES::DEFAULT_KEYLENGTH);
        
        inbuilt_xor((*enc).second, hash, msg, AES::DEFAULT_KEYLENGTH);
        print_text(msg, AES::DEFAULT_KEYLENGTH);

}