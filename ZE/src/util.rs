extern crate bit_vec;
extern crate blake2;
extern crate byteorder;
extern crate pairing;
extern crate rand;

use aes_gcm_siv::aead::NewAead;
use aes_gcm_siv::Aes128GcmSiv;
use bit_vec::BitVec;
use itertools::Itertools;
use pairing::bls12_381::*;
use pairing::*;
use rand::{Rand, Rng, SeedableRng, XorShiftRng};
use sha2::digest::generic_array::GenericArray;
use sha2::{Digest, Sha256};
use std::convert::TryInto;
use std::time::{Duration, Instant};

pub fn do_pairing(g_1: &G1Affine, g_2: &G2Affine) -> Fq12 {
    Bls12::final_exponentiation(&Bls12::miller_loop([&(
        &(*g_1).prepare(),
        &(*g_2).prepare(),
    )]))
    .unwrap()
}

pub fn gen_random_fr(rng: &mut XorShiftRng) -> Fr {
    let sk = Fr::rand(rng);
    sk
}

pub fn gen_random_g1(rng: &mut XorShiftRng) -> G1 {
    let sk = G1::rand(rng);
    sk
}

pub fn gen_random_g2(rng: &mut XorShiftRng) -> G2 {
    let sk = G2::rand(rng);
    sk
}

pub fn gen_random_gt(rng: &mut XorShiftRng) -> Fq12 {
    let sk = Fq12::rand(rng);
    sk
}

pub fn mul_fr_fr(a: Fr, b: &Fr) -> Fr {
    let mut r = &mut a.clone();
    r.mul_assign(b);
    return *r;
}

pub fn mul_g1_fr(a: G1, b: &Fr) -> G1 {
    let mut r = &mut a.clone();
    r.mul_assign(*b);
    return *r;
}
pub fn mul_g2_fr(a: G2, b: &Fr) -> G2 {
    let mut r = &mut a.clone();
    r.mul_assign(*b);
    return *r;
}

pub fn add_fr_fr(a: Fr, b: &Fr) -> Fr {
    let mut r = &mut a.clone();
    r.add_assign(b);
    return *r;
}

pub fn minus_fr_fr(a: Fr, b: &Fr) -> Fr {
    let mut r = &mut a.clone();

    r.sub_assign(b);

    return *r;
}

pub fn add_g1_g1(a: G1, b: G1) -> G1 {
    let mut r = &mut a.clone();
    r.add_assign(&b);
    return *r;
}

pub fn add_g2_g2(a: G2, b: G2) -> G2 {
    let mut r = &mut a.clone();
    r.add_assign(&b);
    return *r;
}

pub fn add_fq12_fq12(a: Fq12, b: Fq12) -> Fq12 {
    let mut r = &mut a.clone();
    r.add_assign(&b);
    return *r;
}

pub fn minus_fq12_fq12(a: Fq12, b: Fq12) -> Fq12 {
    let mut r = &mut a.clone();

    r.sub_assign(&b);

    return *r;
}

pub fn mul_fq12_fq12(a: Fq12, b: Fq12) -> Fq12 {
    let mut r = &mut a.clone();
    r.mul_assign(&b);
    return *r;
}

pub fn fr_inv(a: Fr) -> Fr {
    let mut r = &mut a.clone();
    let k = r.inverse().unwrap();
    k
}

pub fn g1_neg(a: G1) -> G1 {
    let mut r = &mut a.clone();
    r.negate();
    *r
}

pub fn g2_neg(a: G2) -> G2 {
    let mut r = &mut a.clone();
    r.negate();
    *r
}
pub fn gt_inv(a: Fq12) -> Fq12 {
    let mut r = &mut a.clone();
    let k = r.inverse().unwrap();
    k
}

pub fn print_fr(s: &str, a: &Fr) -> () {
    if s != "" {
        println!("This is:{:?}", s);
    }
    println!("element fr:{:?}", *a);
    println!();
}

pub fn print_g1(s: &str, a: &G1) -> () {
    if s != "" {
        println!("This is:{:?}", s);
    }
    println!("element g1:{:?}", *a);
    println!();
}

pub fn print_g2(s: &str, a: &G2) -> () {
    if s != "" {
        println!("This is:{:?}", s);
    }
    println!("element g2:{:?}", *a);
    println!();
}
pub fn print_gt(s: &str, a: &Fq12) -> () {
    if s != "" {
        println!("This is:{:?}", s);
    }
    println!("element gt:{:?}", *a);
    println!();
}
pub fn int_to_fr(i: &u128) -> Fr {
    Fr::from_str(&i.to_string()).unwrap()
}
pub fn int_to_fr_negate(i: &i64) -> Fr {
    let mut neg = Fr::from_str(&i.to_string()).unwrap();
    neg.negate();
    neg
}

// Function to convert Fq element to bytes
pub fn fq_to_bytes(fq: &Fq) -> Vec<u8> {
    let fq_repr = fq.into_repr();
    let mut bytes = vec![0u8; fq_repr.as_ref().len() * 8];
    fq_repr.write_le(&mut bytes[..]).unwrap();
    bytes
}
// Function to convert bytes to BitVec
pub fn convert_to_bits(bytes: &[u8]) -> BitVec {
    let mut bits = BitVec::new();
    for &byte in bytes {
        for i in 0..8 {
            bits.push((byte >> (7 - i)) & 1 == 1);
        }
    }
    bits
}
// Function to convert Fq12 element to BitVec
pub fn fq12_to_bits(fq12: &Fq12) -> BitVec {
    let mut bits = BitVec::new();
    bits.extend(convert_to_bits(&fq_to_bytes(&fq12.c0.c0.c0)));
    bits.extend(convert_to_bits(&fq_to_bytes(&fq12.c0.c0.c1)));
    bits.extend(convert_to_bits(&fq_to_bytes(&fq12.c0.c1.c0)));
    bits.extend(convert_to_bits(&fq_to_bytes(&fq12.c0.c1.c1)));
    bits.extend(convert_to_bits(&fq_to_bytes(&fq12.c0.c2.c0)));
    bits.extend(convert_to_bits(&fq_to_bytes(&fq12.c0.c2.c1)));
    bits.extend(convert_to_bits(&fq_to_bytes(&fq12.c1.c0.c0)));
    bits.extend(convert_to_bits(&fq_to_bytes(&fq12.c1.c0.c1)));
    bits.extend(convert_to_bits(&fq_to_bytes(&fq12.c1.c1.c0)));
    bits.extend(convert_to_bits(&fq_to_bytes(&fq12.c1.c1.c1)));
    bits.extend(convert_to_bits(&fq_to_bytes(&fq12.c1.c2.c0)));
    bits.extend(convert_to_bits(&fq_to_bytes(&fq12.c1.c2.c1)));
    bits
}

// Function to convert Fr element to bytes
pub fn fr_to_bytes(fr: &Fr) -> Vec<u8> {
    let fr_repr = fr.into_repr();
    let mut bytes = vec![0u8; fr_repr.as_ref().len() * 8];
    fr_repr.write_le(&mut bytes[..]).unwrap();
    bytes
}

// Function to convert G1 element to BitVec
pub fn g1_to_bits(g1: &G1) -> BitVec {
    let mut bits = BitVec::new();
    let affine = g1.into_affine();
    let compressed = affine.into_compressed().as_ref().to_vec();
    bits.extend(convert_to_bits(&compressed));
    bits
}

// Function to convert G2 element to BitVec
pub fn g2_to_bits(g2: &G2) -> BitVec {
    let mut bits = BitVec::new();
    let affine = g2.into_affine();
    let compressed = affine.into_compressed().as_ref().to_vec();
    bits.extend(convert_to_bits(&compressed));
    bits
}

pub fn combine_to_fr(
    u: &Fq12,
    epoch_fr: &Fr,
    m: &u128,
    sigma_1_dash: &G1,
    sigma_2_dash: &G1,
    X2: &G2,
    Y_epoch: &G2,
    Y_id: &G2,
    Y_K1: &G2,
) -> Fr {
    let mut combined_bits = BitVec::new();

    // Convert Fq12 to bits
    let fq12_bits = fq12_to_bits(u);
    combined_bits.extend(fq12_bits);
    combined_bits.extend(convert_to_bits(&fr_to_bytes(epoch_fr)));

    // Convert single u128 to bits
    combined_bits.extend(convert_to_bits(&m.to_le_bytes()));

    // Convert G1 to bytes and then to bits
    combined_bits.extend(g1_to_bits(sigma_1_dash));
    combined_bits.extend(g1_to_bits(sigma_2_dash));

    // Convert G2 to bits
    combined_bits.extend(g2_to_bits(X2));
    combined_bits.extend(g2_to_bits(Y_epoch));
    combined_bits.extend(g2_to_bits(Y_id));
    combined_bits.extend(g2_to_bits(Y_K1));

    // Convert combined bits back to a field element Fr
    let combined_bytes = combined_bits.to_bytes();

    // Hash the combined bytes to 256 bits
    let mut hasher = Sha256::new();
    hasher.update(&combined_bytes);
    let hash_result = hasher.finalize();
    // println!("{:?}", hash_result);

    // Convert the hash to a field element Fr
    // Convert hash result to a 256-bit integer
    // Ensure the hash result is of the correct length for FrRepr
    assert!(
        hash_result.len() == 32,
        "Hash result should be 32 bytes long"
    );

    // Create an array of u64 from the hash result
    let mut repr = [0u64; 4];
    for (i, chunk) in hash_result.chunks(8).enumerate() {
        repr[i] = u64::from_le_bytes(chunk.try_into().expect("Chunk should be 8 bytes long"));
    }
    // println!("{:?}", repr);

    // Loop through repr array and convert each element to Fr
    let mut combined_fr = Fr::zero();
    for &value in repr.iter() {
        let fr_repr = FrRepr::from(value);
        let fr_value = Fr::from_repr(fr_repr).expect("Value is not a valid field element");

        combined_fr.add_assign(&fr_value);
    }

    combined_fr
}

/// Hashes an element in G2 to a GenericArray<u8, <Aes128GcmSiv as NewAead>::KeySize>
pub fn hash_g2_to_aes_key(g2: &G2) -> GenericArray<u8, <Aes128GcmSiv as NewAead>::KeySize> {
    let bits = g2_to_bits(g2);
    let element_bytes: Vec<u8> = bits.iter().map(|bit| if bit { 1 } else { 0 }).collect();

    // Hash the bytes using SHA-256
    let mut hasher = Sha256::new();
    hasher.update(&element_bytes);
    let result = hasher.finalize();

    let truncated_result = &result[..16]; // Take the first 16 bytes

    let key = GenericArray::clone_from_slice(truncated_result);

    key
}

pub fn hash_vec_to_g1(vec: Vec<u128>) -> G1 {
    let id_vk = vec.into_iter().fold(0u128, |acc, x| acc.wrapping_add(x));
    hash_int_to_g1(id_vk)
}

pub fn hash_int_to_g1(id: u128) -> G1 {
    let id_fr = int_to_fr(&id);
    let h = G1::one();
    mul_g1_fr(h, &id_fr)
}

pub fn g2_to_vec_u128(g2: G2) -> Vec<u128> {
    let g2_bitvec = g2_to_bits(&g2);
    let g2_vec = bitvec_to_vec_u128(&g2_bitvec);
    g2_vec
}

pub fn combine_vec_u128(vec: Vec<u128>) -> u128 {
    // Check the length of the vector and handle accordingly
    if vec.is_empty() {
        return 0; // or handle as needed for an empty vector
    } else if vec.len() == 1 {
        return vec[0]; // Only one element, return it as is
    }

    // Combine the first two elements
    let high = vec[0];
    let low = vec[1];

    // Shift the high part and OR with the low part
    (high << 64) | low
}

pub fn bitvec_to_vec_u128(bits: &BitVec) -> Vec<u128> {
    let mut result = Vec::new();
    let mut chunk: u128 = 0;
    let mut count = 0;

    for bit in bits.iter() {
        // Set the corresponding bit in the current chunk
        if bit {
            chunk |= 1 << (count % 128);
        }

        // Increment the count
        count += 1;

        // If we've processed 128 bits, push the chunk to the result vector
        if count % 128 == 0 {
            result.push(chunk);
            chunk = 0;
        }
    }

    // If there are remaining bits, push the last chunk
    if count % 128 != 0 {
        result.push(chunk);
    }

    result
}

pub fn convert_g2_to_fr(ek: &G2) -> Fr {
    let ek_u128_vec = g2_to_vec_u128(*ek);
    let ek_u128 = combine_vec_u128(ek_u128_vec);
    int_to_fr(&ek_u128)
}

#[derive(Clone, Debug)]
pub struct CertV {
    pub sk: Fr,
    pub pk: G2,
    pub sig_e: G1,
}
#[derive(Clone, Debug)]
pub struct IASecretKey {
    pub sk_x2: Fr,
    pub sk_id: Fr,
    pub sk_epoch: Fr,
    pub sk_k1: Fr,
}
#[derive(Clone, Debug, Copy)]
pub struct IAPublicKey {
    pub pk_X2: G2,
    pub pk_id: G2,
    pub pk_epoch: G2,
    pub pk_K1: G2,
    pub g2: G2,
}
