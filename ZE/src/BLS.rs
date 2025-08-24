extern crate blake2;
extern crate byteorder;
extern crate pairing;
extern crate rand;

use std::collections::HashSet;

use pairing::bls12_381::*;
use pairing::*;
use rand::{SeedableRng, XorShiftRng};

use crate::util::*;

// Key generation
pub fn bls_key_gen(rng: &mut XorShiftRng) -> (G2, Fr) {
    // let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
    let g2 = G2::one();

    //let mut rng = OsRng::new().unwrap();

    let sk = gen_random_fr(rng);

    let vk = mul_g2_fr(g2, &sk);

    (vk, sk)
}

pub fn bls_sign_vid_vpk(sk: &Fr, vid: u128, vk: &G2, sete: &mut HashSet<u128>) -> Option<G1> {
    if sete.contains(&vid) {
        println!("Error: {} is already in the set", vid);
        None
    } else {
        sete.insert(vid);
        let mut vk_vid__vec = g2_to_vec_u128(*vk);
        vk_vid__vec.push(vid);
        let h = hash_vec_to_g1(vk_vid__vec);
        let sig = mul_g1_fr(h, &sk);
        Some(sig)
    }
}

pub fn bls_verify_vid_vpk(pk: &G2, vid: u128, vk: G2, sign: &G1) -> bool {
    let g2 = G2::one();
    let mut vk_vid__vec = g2_to_vec_u128(vk);
    vk_vid__vec.push(vid);
    let h = hash_vec_to_g1(vk_vid__vec);
    let left_pair = do_pairing(&sign.into_affine(), &g2.into_affine());
    let right_pair = do_pairing(&h.into_affine(), &pk.into_affine());

    left_pair == right_pair
}

pub fn bls_sign_epoch(sk: &Fr, e: u128) -> G1 {
    let h = hash_int_to_g1(e);
    let sig = mul_g1_fr(h, &sk);
    sig
}

pub fn bls_verify_epoch(pk: &G2, e: u128, sign: &G1) -> bool {
    let g2 = G2::one();
    let h = hash_int_to_g1(e);
    let left_pair = do_pairing(&sign.into_affine(), &g2.into_affine());
    let right_pair = do_pairing(&h.into_affine(), &pk.into_affine());
    // println!("{:?}\n", left_pair);
    // println!("{:?}\n", right_pair);
    left_pair == right_pair
}
