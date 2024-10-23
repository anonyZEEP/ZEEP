#include <bits/stdc++.h>
#include <pbc.h>

int main(){
    char param[1024];
    FILE *stream = fopen("bls12-446.param", "r");
    size_t count = fread(param, 1, 1024, stream);
    if (!count) pbc_die("input error");
    pairing_s* k = (pairing_s*)malloc(sizeof(*(k)));
    pairing_init_set_buf(k, param, count);
    element_s a,b,c;
    element_init_Zr(&a, k);
    element_random(&a);

    element_init_G1(&b, k);
    element_random(&b);

    
    element_init_GT(&c, k);
    element_random(&c);

    element_printf("a %B\n", &a);
    element_printf("b %B\n", &b);
    element_printf("c %B\n", &c);

    int size_a = element_length_in_bytes(&a);
    int size_b = element_length_in_bytes_compressed(&b);
    int size_c = element_length_in_bytes_compressed(&c);

    std::cout<<3*size_a + 2*size_b<<std::endl;

    std::cout<<size_a <<std::endl;
    // std::cout<<size_b<<std::endl;
    // std::cout<<size_c<<std::endl;
    return 0;
}