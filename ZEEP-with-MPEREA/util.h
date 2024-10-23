
#include <bits/stdc++.h>
#include <pbc.h>
#include <gmp.h>
#include "PS_Commit.h"
// class sig{
//     public:
//     element_s *a_d;
//     element_s *sig1;
//     element_s *sig2;

//     sig(params p){
        
//         element_init_Zr(a_d, &p.e);
//         element_init_G1(sig1, &p.e);
//         element_init_G1(sig2, &p.e);
        
//         // element_random(&a_d);
//         // element_random(&sig1);
//         // element_random(&sig2);
//     }
//     void assign_val(element_s *a, element_s *b, element_s *c, params p){
//          element_printf("a = %B\n\n",a);
//          element_printf("b = %B\n\n",b);
//          element_printf("c = %B\n\n",c);

//          int size_a = element_length_in_bytes(a);
//          int size_b = element_length_in_bytes(b);
//          int size_c = element_length_in_bytes(c);
//          //int f = element_length_in_bytes(a_d);
//          std::cout<<size_a<<" size_a"<<std::endl;
//          std::cout<<size_b<<" size_b"<<std::endl;
//          std::cout<<size_c<<" size_c"<<std::endl;
//          //std::cout<<f<<" f"<<std::endl;
         
        

//         element_set(&a_d,a);
//         element_set(&sig1,b);
//         element_set(&sig2, c);
//     }
// };