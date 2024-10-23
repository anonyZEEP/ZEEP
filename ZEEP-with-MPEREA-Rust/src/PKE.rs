extern crate blake2;
extern crate byteorder;
extern crate pairing;
extern crate rand;

use pairing::bls12_381::{Fr, G2};
use pairing::CurveProjective;
use rand::XorShiftRng;

use crate::util::*;

// Key generation
pub fn pke_key_gen(rng: &mut XorShiftRng) -> (G2, Fr) {
    let g2 = G2::one();
    let sk = gen_random_fr(rng);
    let vk = mul_g2_fr(g2, &sk);
    (vk, sk)
}

pub fn pke_encrypt(rng: &mut XorShiftRng, pk: G2, plaintext: G2) -> (G2, G2) {
    let g = G2::one();
    let k = gen_random_fr(rng);
    let c_1 = mul_g2_fr(g, &k);
    let c_2 = add_g2_g2(mul_g2_fr(pk, &k), plaintext);

    (c_1, c_2)
}

pub fn pke_decrypt(sk: &Fr, ciphertext: (G2, G2)) -> G2 {
    let (c_1, c_2) = ciphertext;
    let c_1_sk = mul_g2_fr(c_1, &sk);

    let plaintext = add_g2_g2(c_2, g2_neg(c_1_sk));

    plaintext
}
