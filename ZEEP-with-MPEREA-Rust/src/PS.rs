extern crate blake2;
extern crate byteorder;
extern crate pairing;
extern crate rand;

use pairing::bls12_381::*;
use pairing::*;
use rand::XorShiftRng;
use std::collections::VecDeque;

use crate::util::{
    self, add_g1_g1, add_g2_g2, do_pairing, gen_random_fr, get_random_rng, minus_fr_fr, minus_g1_g1, mul_fr_fr, mul_g1_fr, mul_g2_fr, Hash_into_Fr, PS_pk, PS_sk
};

pub fn ps_keygen(rng: &mut XorShiftRng, k: u64) -> (PS_sk, PS_pk) {
    let g = G1::one();
    let g_dash = G2::one();

    let x = util::gen_random_fr(rng);

    let mut y = Vec::with_capacity(k.try_into().unwrap());

    for i in 0..(k + 1) {
        let yi = util::gen_random_fr(rng);
        y.push(yi);
    }

    let mut Y = Vec::with_capacity(k.try_into().unwrap());

    let X = util::mul_g1_fr(g, &x);

    for i in 0..(k + 1) {
        let Yi = mul_g1_fr(g, &y[i as usize]);
        Y.push(Yi);
    }

    let mut Y_dash: Vec<G2> = Vec::with_capacity(k.try_into().unwrap());

    let X_dash = util::mul_g2_fr(g_dash, &x);

    for i in 0..(k + 1) {
        let Y_dashi = mul_g2_fr(g_dash, &y[i as usize]);
        Y_dash.push(Y_dashi);
    }

    let sk: PS_sk = util::PS_sk { X: X }; // Assuming PS_sk can be derived from X
    let pk: PS_pk = util::PS_pk {
        g,
        g_dash,
        Y,
        X_dash,
        Y_dash,
    };

    (sk, pk)
}

pub fn GenCommitment(
    PS_pk: &PS_pk,
    message_q: &mut VecDeque<Fr>,
    k: u64,
) -> (G1, (Fr, Fr, Vec<Fr>), Fr) {
    let g = PS_pk.g;
    let Y = &PS_pk.Y;
    let r = gen_random_fr(&mut get_random_rng());
    let mut commit = mul_g1_fr(PS_pk.g, &r);

    for (y_element, message_element) in Y.iter().zip(message_q.iter()) {
        commit = add_g1_g1(commit, mul_g1_fr(*y_element, message_element));
    }

    // generate new random

    let mut pie_rt: Vec<Fr> = Vec::with_capacity(k.try_into().unwrap());

    let pie_r = gen_random_fr(&mut get_random_rng());

    for i in 0..k {
        let rt_i = gen_random_fr(&mut get_random_rng());
        pie_rt.push(rt_i);
    }

    // gen G1 elements fro mrandim

    let pie_Yt: Vec<G1> = Vec::with_capacity(k.try_into().unwrap());

    let mut commit_r = mul_g1_fr(g, &pie_r);

    for i in 0..k {
        commit_r = add_g1_g1(commit_r, mul_g1_fr(Y[i as usize], &pie_rt[i as usize]));
    }

    let c = Hash_into_Fr(commit_r, Y.to_vec());

    let sr = minus_fr_fr(pie_r, &mul_fr_fr(c, &r));
    let mut s_tr: Vec<Fr> = Vec::with_capacity(k.try_into().unwrap());

    for (i, mt) in (0..k).zip(message_q.iter()) {
        let str_i = minus_fr_fr(pie_rt[i as usize], &mul_fr_fr(c, mt));
        s_tr.push(str_i);
    }

    (commit, (c, sr, s_tr), r)
}


pub fn sign(
    pie_c: &(Fr, Fr, Vec<Fr>),
    commit: &G1,
    epoch: Fr,
    PS_sk: &PS_sk,
    PS_pk: &PS_pk,
    k: u64,
) -> Option<(G1, G1, G1)> {
    let g = PS_pk.g;
    let Y = &PS_pk.Y;
    let (c, sr, s_tr) = pie_c;
    let mut commit_r_dash = mul_g1_fr(g, &sr);

    for i in 0..k {
        commit_r_dash = add_g1_g1(commit_r_dash, mul_g1_fr(Y[i as usize], &s_tr[i as usize]));
    }

    commit_r_dash = add_g1_g1(commit_r_dash, mul_g1_fr(*commit, &c));

    let c_dash = Hash_into_Fr(commit_r_dash, Y.to_vec());
    
    if *c == c_dash {
        println!("Verify\n");
        let commit_dash = add_g1_g1(*commit, mul_g1_fr(Y[k as usize], &epoch));
        let u = gen_random_fr(&mut get_random_rng());
        let sigma_1 = mul_g1_fr(g, &u);
        let sigma_2 = mul_g1_fr(add_g1_g1(PS_sk.X, commit_dash), &u);
        let sigma = (sigma_1, sigma_2, commit_dash);
        Some(sigma)
    } else {
        println!("Not Verify at PS sign\n");
        None
    }
}

pub fn Unblind(sigma: &mut (G1, G1), r: Fr) -> (G1, G1) {
    println!("sigma_2 : {:?}\n", { sigma.1.into_affine() });

    sigma.1 = minus_g1_g1(sigma.1, mul_g1_fr(sigma.0, &r));
    println!("sigma_2_new : {:?}\n", { sigma.1.into_affine() });
    return *sigma;
}

pub fn verify(
    sigma: (G1, G1),
    message_q: &mut VecDeque<Fr>,
    epoch: Fr,
    PS_pk: &PS_pk,
    k: u64,
) -> bool {
    let (sigma_1, sigma_2) = sigma;

    if sigma_1 == G1::zero() {
        false
    } else {
        println!("sigma_2_modified: {:?}", sigma_2.into_affine());
        let g_dash = PS_pk.g_dash;

        let Y_dash = &PS_pk.Y_dash;

        let mut pair1_elem2 = PS_pk.X_dash;

        for (i, mt) in (0..k).zip(message_q.iter()) {
            pair1_elem2 = add_g2_g2(pair1_elem2, mul_g2_fr(Y_dash[i as usize], mt));
        }

        pair1_elem2 = add_g2_g2(pair1_elem2, mul_g2_fr(Y_dash[k as usize], &epoch));

        let pair1 = do_pairing(&sigma_1.into_affine(), &pair1_elem2.into_affine());

        let pair2 = do_pairing(&sigma_2.into_affine(), &g_dash.into_affine());

        pair1 == pair2
    }
}
