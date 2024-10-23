extern crate blake2;
extern crate byteorder;
extern crate pairing;
extern crate rand;

use pairing::bls12_381::*;
use pairing::*;
use std::collections::VecDeque;


use crate::util::*;
use crate::Accumulator::{nonmem_create, ver_nonmem};
use crate::PS::*;

pub fn zkp_sign_q(
    sign: (G1, G1),
    PS_pk: &PS_pk,
    commit: G1,
    commit_dash: G1,
    message_q: &mut VecDeque<Fr>,
    r1: Fr,
    r2: Fr,
    t1: Fr,
) -> (Fr, (Fr, Fr, Fr, Fr, Fr), G1, G1, G1, G1, Fq12, Fr) {
    let r = gen_random_fr(&mut get_random_rng());
    let t4 = message_q.back().unwrap();
    let r1_hat = gen_random_fr(&mut get_random_rng());
    let r2_hat = gen_random_fr(&mut get_random_rng());
    let t1_hat = gen_random_fr(&mut get_random_rng());
    let t2_hat = gen_random_fr(&mut get_random_rng());
    let t4_hat = gen_random_fr(&mut get_random_rng());

    let (sign1, sign2) = sign;

    let u = mul_fq12_fq12(do_pairing(&mul_g1_fr(sign1, &mul_fr_fr(r, &t1_hat)).into_affine(), &PS_pk.Y_dash[0].into_affine()),
     do_pairing(&mul_g1_fr(sign1, &mul_fr_fr(r, &t2_hat)).into_affine(), &PS_pk.Y_dash[1].into_affine()));

    let p1 = add_g1_g1(mul_g1_fr(PS_pk.g, &r1_hat), add_g1_g1(mul_g1_fr(PS_pk.Y[0], &t1_hat), mul_g1_fr(PS_pk.Y[1], &t2_hat)));
    let p2 = add_g1_g1(mul_g1_fr(PS_pk.g, &r2_hat), add_g1_g1(mul_g1_fr(PS_pk.Y[0], &t2_hat), mul_g1_fr(PS_pk.Y[2], &t4_hat)));

    let c = MP_Hash_into_Fr(u, p1, p2, sign1, sign2, commit, commit_dash, PS_pk);

    let t1_t1 = minus_fr_fr(t1_hat, &mul_fr_fr(c, &t1));
    let t2_t2 = minus_fr_fr(t2_hat, &mul_fr_fr(c, &message_q.get(0).unwrap()));
    let t4_t4 = minus_fr_fr(t4_hat, &mul_fr_fr(c, &t4));

    let response = (minus_fr_fr(r1_hat, &mul_fr_fr(c, &r1)), minus_fr_fr(r2_hat, &mul_fr_fr(c, &r2)), t1_t1, t2_t2, t4_t4);
    
    (c, response, commit, commit_dash, sign1, sign2, u, r)
}

pub fn zkp_sign_q_verify(
    PS_pk: &PS_pk,
    epoch: Fr,
    zkpok: (Fr, (Fr, Fr, Fr, Fr, Fr), G1, G1, G1, G1, Fq12, Fr),
    t3: Fr
) -> bool {

    let (c, response, c1, c2, sign1, sign2, u, r) = zkpok;
    let(v1, v2, v3, v4, v5) = response;
    
    let e1 = do_pairing(&mul_g1_fr(sign1, &v3).into_affine(), &mul_g2_fr(PS_pk.Y_dash[0], &r).into_affine());
    let e2 = do_pairing(&mul_g1_fr(sign1, &v4).into_affine(), &mul_g2_fr(PS_pk.Y_dash[1], &r).into_affine());
    let e3 = do_pairing(&mul_g1_fr(sign2, &c).into_affine(), &mul_g2_fr(PS_pk.g_dash, &r).into_affine());
    let e4 = do_pairing(&mul_g1_fr(mul_g1_fr(sign1, &c), &r).into_affine(), &add_g2_g2(g2_neg(PS_pk.X_dash), 
                   add_g2_g2(g2_neg(mul_g2_fr(PS_pk.Y_dash[2], &t3)), g2_neg(mul_g2_fr(PS_pk.Y_dash[3], &epoch)))).into_affine());
    let u1 = mul_fq12_fq12(e1, mul_fq12_fq12(e2, mul_fq12_fq12(e3, e4)));

    let c1_dash = add_g1_g1(c1, g1_neg(mul_g1_fr(PS_pk.Y[2], &t3)));
    let c2_dash = add_g1_g1(c2, g1_neg(mul_g1_fr(PS_pk.Y[1], &t3)));

    let p1_1 = add_g1_g1(mul_g1_fr(c1_dash, &c), mul_g1_fr(PS_pk.g, &v1));
    let p1_2 = add_g1_g1(mul_g1_fr(PS_pk.Y[0], &v3), mul_g1_fr(PS_pk.Y[1], &v4));
    let p1 = add_g1_g1(p1_1, p1_2);

    let p2_1 = add_g1_g1(mul_g1_fr(c2_dash, &c), mul_g1_fr(PS_pk.g, &v2));
    let p2_2 = add_g1_g1(mul_g1_fr(PS_pk.Y[0], &v4), mul_g1_fr(PS_pk.Y[2], &v5));
    let p2 = add_g1_g1(p2_1, p2_2);

    let c_dash = MP_Hash_into_Fr(u1, p1, p2, sign1, sign2, c1, c2, &PS_pk);

    c == c_dash 
}

pub fn register_user_s1(
    PS_pk: &PS_pk,
    message_q: &mut VecDeque<Fr>,
    k: u64,
) -> ((G1, (Fr, Fr, Vec<Fr>), Fr), Fr) {
    let q_star = gen_random_fr(&mut get_random_rng());
    let q_hat = message_q.pop_front().unwrap();
    message_q.push_back(q_star);
    let commit_pie = GenCommitment(PS_pk, message_q, k);
    (commit_pie, q_star)
}
/* 
pub fn register_user_i(
    commit_pie: &(G1, (Fr, Fr, Vec<Fr>), Fr),
    epoch: Fr,
    PS_sk: &PS_sk,
    PS_pk: &PS_pk,
    k: u64,
    g: G1,
    s: &Vec<Fr>,
    sk: Fr,
    q_hat: Fr
) -> Option<((G1, G1, G1), (G1, Fr))> {
    let (commit, pie_r, r) = commit_pie;
    let sigma_star = sign(pie_r, commit, epoch, PS_sk, PS_pk, k);
    if(sigma_star == None){
        println!("Not Verify\n");
        None
    }else{
        let wt = nonmem_create(sk, s, q_hat, g);
        Some((sigma_star.unwrap(), wt))
    }

}
    */

pub fn authenticate_user_s1(
    cred: (&mut VecDeque<Fr>, Fr, (G1, G1), (G1, Fr), G1),
    PS_pk: &PS_pk,
    k: u64,
    commit_1: &(G1, (Fr, Fr, Vec<Fr>), Fr),
    e_j: Fr
) -> (Fr, Fr, (G1, G1), (Fr, (Fr, Fr, Fr, Fr, Fr), G1, G1, G1, G1, Fq12, Fr), (G1, (Fr, Fr, Vec<Fr>), Fr), Fr){
    let (mut message_q, e_i, sigma, wt, vt) = cred;
    let q_star = gen_random_fr(&mut get_random_rng());
    let q_hat = message_q.pop_front().unwrap();
    let q_k = *message_q.back().unwrap();
    message_q.push_back(q_star);
    let commit_2 = GenCommitment(PS_pk, message_q, k);
    let r_dash = gen_random_fr(&mut get_random_rng());
    let sigma_r1 = (mul_g1_fr(sigma.0, &r_dash), mul_g1_fr(sigma.1, &r_dash));
    let zkpok_q_sigma = zkp_sign_q(sigma_r1, PS_pk, commit_1.0, commit_2.0, message_q, commit_1.2, commit_2.2, q_hat);
    (q_k, cred.1, sigma_r1, zkpok_q_sigma, commit_2, e_j)
}
 
pub fn authenticate_user_i(
    PS_sk: &PS_sk,
    PS_pk: &PS_pk,
    req: &(Fr, Fr, (G1, G1), (Fr, (Fr, Fr, Fr, Fr, Fr), G1, G1, G1, G1, Fq12, Fr), (G1, (Fr, Fr, Vec<Fr>), Fr), Fr),
    e_j_1: Fr,
    k: u64,
    g: G1,
    s: &Vec<Fr>,
    sk: Fr,
    
) -> Option<((G1, G1, G1), (G1, Fr))> {
    let zkpok_ch = zkp_sign_q_verify(PS_pk, req.1, req.3, req.0);
    let sigma_star = sign(&req.4.1, &req.4.0, e_j_1, PS_sk, &PS_pk, k);
    if(sigma_star == None || zkpok_ch == false){
        println!("Not Verify\n");
        None
    }else{
        let wt = nonmem_create(sk, s, req.0, g);
        Some((sigma_star.unwrap(), wt))
    }

}

pub fn register_user_s2(
    sigma_r: (G1, G1, G1),
    message_q: &mut VecDeque<Fr>,
    epoch: Fr,
    vt: G1,
    PS_pk: & PS_pk,
    k: u64,
    q_hat: Fr,
    wt: (G1, Fr),
    a_pk: G2,
    g: G1,
    r: Fr
) -> Option<(Fr, (G1, G1), (G1, Fr), G1)> {
    let  (sigma_1, sigma_2, _) = sigma_r;
    let sigma_un = Unblind(&mut (sigma_1, sigma_2), r);
    let sigma_ver = verify(sigma_un, message_q, epoch, PS_pk, k);
    let wt_ver = ver_nonmem(vt, q_hat, wt, a_pk, g);
    if(sigma_ver == false || wt_ver == false){
        println!("Not Verify\n");
        None
    }else{
        Some((epoch, sigma_un, wt, vt))
    }
}

/* 
extern crate blake2;
extern crate byteorder;
extern crate pairing;
extern crate rand;

use pairing::bls12_381::*;
use pairing::*;
use rand::XorShiftRng;
use std::collections::VecDeque;
use std::iter::Product;

use crate::util::*;

pub fn keygen(rng: &mut XorShiftRng)->(G1, G2, Fr) {
    let g = G1::one();
    let g2 = G2::one();
    let sk = gen_random_fr(rng);
    let pk = mul_g2_fr(g2, &sk);
    (g, pk, sk)
}

pub fn add(sk: Fr, vt: G1, x: Fr) -> G1{
    mul_g1_fr(vt, &add_fr_fr(sk, &x))
}

pub fn nonmem_create(sk: Fr, s: &Vec<Fr>, x: Fr, g: G1) -> (G1, Fr, Fr, Fr, G2){
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
    let g2 = G2::one();
    let h2 = gen_random_fr(&mut get_random_rng());
    let r = gen_random_fr(&mut get_random_rng());
    let ci = add_g2_g2(mul_g2_fr(g2, &mul_fr_fr(h2, &r)), mul_g2_fr(g2, &sk_x));
    (c, dd, h2, r, ci)
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
    */