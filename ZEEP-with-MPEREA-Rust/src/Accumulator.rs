extern crate blake2;
extern crate byteorder;
extern crate pairing;
extern crate rand;

use pairing::bls12_381::*;
use pairing::*;
use rand::XorShiftRng;
use crate::util::*;

pub fn keygen(rng: &mut XorShiftRng)->( G2, Fr) {
    let g2 = G2::one();
    let sk = gen_random_fr(rng);
    let pk = mul_g2_fr(g2, &sk);
    (pk, sk)
}

pub fn add(sk: Fr, vt: G1, x: Fr) -> G1{
    mul_g1_fr(vt, &add_fr_fr(sk, &x))
}

pub fn nonmem_create(sk: Fr, s: &Vec<Fr>, x: Fr, g: G1) -> (G1, Fr){
    let vec_u: Vec<Fr>= s.iter().map(|xi| add_fr_fr(*xi, &sk)).collect();
    let &(mut u) = vec_u.get(0).unwrap();
    for &e in &vec_u[1..] {
        let a: Fr = mul_fr_fr(u, &e);
        u = a;
    }
    let vec_dd: Vec<Fr>= s.iter().map(|xi| minus_fr_fr(*xi, &x)).collect();
    let &(mut dd) = vec_dd.get(0).unwrap();
    for &e in &vec_dd[1..] {
        let a: Fr = mul_fr_fr(dd, &e);
        dd = a;
    }
    
    let sk_x = add_fr_fr(sk, &x);
    let c = mul_g1_fr(g, &mul_fr_fr(minus_fr_fr(u, &dd), &fr_inv(sk_x)));
    dd.negate();
    //let c = mul_g2_fr(g, &u);
    (c, dd)
}

pub fn nonmem_update(vt: G1, x: Fr, y: Fr, (c, d): (G1, Fr)) -> (G1, Fr){
    let c1 = add_g1_g1(vt, mul_g1_fr(c, &minus_fr_fr(y, &x)));
    let d1 = mul_fr_fr(d, &minus_fr_fr(y, &x));
    (c1, d1)
}

pub fn ver_nonmem(vt: G1, x: Fr, (c, d): (G1, Fr), pk: G2, g: G1) -> bool {
    if d.is_zero(){
        false
    }else{
        let g2 = G2::one();
         
        let left_pair = do_pairing(&c.into_affine(), &add_g2_g2(mul_g2_fr(g2, &x), pk).into_affine());
        let right_pair1 = do_pairing(&g.into_affine(), &mul_g2_fr(g2, &d).into_affine());
        
        //let left_pair = do_pairing(&g1.into_affine(), &c.into_affine());
        let right_pair2 = do_pairing(&vt.into_affine(), &g2.into_affine());
        let right_pair = mul_fq12_fq12(right_pair1, right_pair2);
        left_pair == right_pair
    }
    
}


pub fn zkp_non_mem(
    g1: G1,
    g2: G2,
    wt: (G1, Fr),
    vt: G1,
    y: Fr,
    pk: G2,
)  -> (Fr, Fr, Fr, Fr, Fr, Fr, Fr, G2, G1, G1, G2, G1, G2, G2, Fq12){
    let g_hat = mul_g1_fr(g1, &gen_random_fr(&mut get_random_rng()));
    let g = G1::one();
    let h22 = gen_random_fr(&mut get_random_rng());
    let h_hat = mul_g2_fr(g2, &gen_random_fr(&mut get_random_rng()));
    
    let r = gen_random_fr(&mut get_random_rng());
    let g2_y = mul_g2_fr(g2, &y);
    let ci = add_g2_g2(mul_g2_fr(g2, &mul_fr_fr(h22, &r)), add_g2_g2(g2_y, pk));
    
    let h2 = mul_g2_fr(g2, &h22);
    let tau_1 = gen_random_fr(&mut get_random_rng());
    let tau_3 = gen_random_fr(&mut get_random_rng());
    let tau_4 = gen_random_fr(&mut get_random_rng());
    let ro_3 = mul_fr_fr(tau_3, &r);
    let ro_4 = mul_fr_fr(tau_4, &r);
    
    let r_r = gen_random_fr(&mut get_random_rng());
    let r_tau_1 = gen_random_fr(&mut get_random_rng());
    let r_tau_3 = gen_random_fr(&mut get_random_rng());
    let r_tau_4 = gen_random_fr(&mut get_random_rng());
    let r_ro_3 = gen_random_fr(&mut get_random_rng());
    let r_ro_4 = gen_random_fr(&mut get_random_rng());
    let (beta, alpha) = wt;
    let a2_hat = add_g2_g2(mul_g2_fr(g2, &alpha), mul_g2_fr(h_hat, &tau_1));
    let b1_hat = add_g1_g1(mul_g1_fr(g1, &tau_3), mul_g1_fr(g_hat, &tau_4));
    let b2_hat = add_g1_g1(beta, mul_g1_fr(g_hat, &tau_3));
    let r21 = add_g1_g1(mul_g1_fr(g1, &r_tau_3), mul_g1_fr(g_hat, &r_tau_4));
    let r22 = add_g1_g1(mul_g1_fr(b1_hat, &r_r), add_g1_g1(g1_neg(mul_g1_fr(g1, &r_ro_3)), g1_neg(mul_g1_fr(g_hat, &r_ro_4))));

    let p1 = do_pairing(&vt.into_affine(), &mul_g2_fr(h_hat, &r_tau_1).into_affine());
    let p2 = do_pairing(&mul_g1_fr(g_hat, &r_tau_3).into_affine(), &ci.into_affine());
    let p3 = fq12_inv(do_pairing(&g_hat.into_affine(), &mul_g2_fr(h2, &r_ro_3).into_affine()));
    let p4 = do_pairing(&b2_hat.into_affine(), &mul_g2_fr(h2, &r_r).into_affine());
    let r3 = mul_fq12_fq12(mul_fq12_fq12(p1, p2), mul_fq12_fq12(p3, p4));
    
    let c = wt_Hash_into_Fr(r21, r22, r3, a2_hat, b1_hat, b2_hat, g_hat, h2, h_hat);
    let sr = add_fr_fr(r_r, &mul_fr_fr(c, &r));
    let s_tau_1 = add_fr_fr(r_tau_1, &mul_fr_fr(c, &tau_1));
    let s_tau_3 = add_fr_fr(r_tau_3, &mul_fr_fr(c, &tau_3));
    let s_tau_4 = add_fr_fr(r_tau_4, &mul_fr_fr(c, &tau_4));
    let s_ro_3 = add_fr_fr(r_ro_3, &mul_fr_fr(c, &ro_3));
    let s_ro_4 = add_fr_fr(r_ro_4, &mul_fr_fr(c, &ro_4));
    
    (sr, s_tau_1, s_tau_3, s_tau_4, s_ro_3, s_ro_4, c, a2_hat, b1_hat, b2_hat, ci, g_hat, h2, h_hat, r3)
}

pub fn zkp_non_mem_ver(
    zkp_wt: (Fr, Fr, Fr, Fr, Fr, Fr, Fr, G2, G1, G1, G2, G1, G2, G2, Fq12),
    g1: G1,
    g2: G2,
    vt: G1
) -> bool {
    let r21 = add_g1_g1(g1_neg(mul_g1_fr(zkp_wt.8, &zkp_wt.6)), add_g1_g1(mul_g1_fr(g1, &zkp_wt.2), mul_g1_fr(zkp_wt.11, &zkp_wt.3)));
    let r22 = add_g1_g1(mul_g1_fr(zkp_wt.8, &zkp_wt.0), add_g1_g1(g1_neg(mul_g1_fr(g1, &zkp_wt.4)), g1_neg(mul_g1_fr(zkp_wt.11, &zkp_wt.5))));
    let p1 = do_pairing(&vt.into_affine(), &mul_g2_fr(zkp_wt.13, &zkp_wt.1).into_affine());
    let p2 = do_pairing(&mul_g1_fr(zkp_wt.11, &zkp_wt.2).into_affine(), &zkp_wt.10.into_affine());
    let p3 = fq12_inv(do_pairing(&zkp_wt.11.into_affine(), &mul_g2_fr(zkp_wt.12, &zkp_wt.4).into_affine()));
    let p4 = do_pairing(&zkp_wt.9.into_affine(), &mul_g2_fr(zkp_wt.12, &zkp_wt.0).into_affine());
    let r3_1 = mul_fq12_fq12(mul_fq12_fq12(p1, p2), mul_fq12_fq12(p3, p4));
    let r3_2 = mul_fq12_fq12(r3_1, do_pairing(&mul_g1_fr(g1, &zkp_wt.6).into_affine(), &g2.into_affine()));
    
    let r3 = mul_fq12_fq12(r3_2, fq12_inv(mul_fq12_fq12(do_pairing(&mul_g1_fr(vt, &zkp_wt.6).into_affine(), &zkp_wt.7.into_affine()), do_pairing(&mul_g1_fr(zkp_wt.9, &zkp_wt.6).into_affine(), &zkp_wt.10.into_affine()))));
    let c = wt_Hash_into_Fr(r21, r22, r3, zkp_wt.7, zkp_wt.8, zkp_wt.9, zkp_wt.11, zkp_wt.12, zkp_wt.13);
    c == zkp_wt.6
}