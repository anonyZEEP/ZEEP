extern crate bit_vec;
extern crate sha2;
extern crate pairing;
extern crate rand;
extern crate blake2;
extern crate byteorder;

use self::bit_vec::BitVec;
use self::sha2::{digest, Sha256};
use byteorder::{ReadBytesExt, BigEndian,ByteOrder, NativeEndian};
use rand::{SeedableRng, Rng, Rand,XorShiftRng};
use rand::chacha::ChaChaRng;
use pairing::bls12_381::*;
use pairing::*;
use blake2::{Blake2b, Digest, Blake2s};
use std::fmt;
use std::time::{Duration, Instant};
use std::convert::TryInto;
use std::convert::TryFrom;

#[derive(Clone, Debug, PartialEq)]
pub enum ticket_status {
    ACTIVE,
    JUDGED,
    DEFAULT,
}

#[derive(Clone, Debug)]
pub struct curr_sess{
    pub K: usize,
    pub M: usize,
    pub q: Fr
}

impl Default for curr_sess {
    fn default () -> curr_sess {
        let zero = Fr::from_str(&0.to_string()).unwrap();
        let z = usize::try_from(0).unwrap();
        curr_sess{K: z, M:z ,q: zero}
    }
}

#[derive(Clone, Debug)]
pub struct session{
    pub id: Fr,
    pub score: Fr,
    pub bbs_sig: Box<bbs_sign>,
    pub bb_sig: G1,
    pub status: ticket_status
}
impl session {

    pub fn print_val(&mut self){
        print_fr(&self.id);
        print_fr(&self.score);
        self.bbs_sig.print_val();
        print_g1(&self.bb_sig);
    }
}

#[derive(Clone, Debug)]
pub struct bbs_sign{
    pub A: Box<G1>,
    pub e: Box<Fr>,
    pub y: Box<Fr>
}
impl bbs_sign{

    pub fn print_val(&mut self){

        print_g1(&self.A);
        print_fr(&self.e);
        print_fr(&self.y);
    }
    
}

impl Default for bbs_sign {
    fn default () -> bbs_sign {
        let zero = Fr::from_str(&0.to_string()).unwrap();
        bbs_sign{A: Box::new(G1::one()), e:Box::new( zero) , y:Box::new( zero)}
    }
}

#[derive(Clone, Debug)]
pub struct bbs_zkp{

    pub k: u32,
    pub B: Box<Fr>,
    pub A1: Box<G1>,
    pub A2: Box<G1>,
    pub T1: Box<G1>,
    pub T2: Box<G1>,
    pub z_x: Box<Fr>,
    pub z_s: Box<Fr>, 
    pub z_A: Box<Fr>,
    pub z_e: Box<Fr>,
    pub z_B: Box<Fr>,
    pub z_y: Box<Fr>,
    pub z: Box<Vec<Fr>>,
    pub challenge: Box<Fr>

}
#[derive(Clone, Debug)]
pub struct score_zkp{

    pub Beta: Box<Vec<Fr>>,
    pub D: Box<Vec<G1>>,
    pub B: Box<Vec<G1>>,
    pub S: Box<Vec<G1>>,
    pub T: Box<Vec<G1>>,
    pub W: Box<Vec<G1>>,
    pub z_ui: Box<Vec<Fr>>,
    pub z_si: Box<Vec<Fr>>,
    pub z_Bi: Box<Vec<Fr>>,
    pub z_yi: Box<Vec<Fr>>,
    pub z_ei: Box<Vec<Fr>>,
    pub challenge: Box<Fr>
}

#[derive(Clone, Debug)]
pub struct randoms{
    pub delta_i: Box<Vec<Fr>>,
    pub lambda_i: Box<Vec<Fr>>,
    pub gamma_i: Box<Vec<Fr>>,
    pub theta_i: Box<Vec<Fr>>
}


#[derive(Clone, Debug)]
pub struct credential{
    pub x: Box<Fr>,
    pub q: Box<Fr>,
    pub score: Box<Fr>,
    pub tickets: Box<Vec<Box<Fr>>>
}

impl Default for credential {
    fn default () -> credential {
        let zero = Fr::from_str(&0.to_string()).unwrap();
        let tik  = Box::new(Vec::new());
        credential{x: Box::new(zero), q:Box::new(zero) , score:Box::new(zero), tickets: tik}
    }
}
#[derive(Clone)]
pub struct P_iss_ZKP{
    pub challenge: Box<Fr>,
    pub s_x: Box<Fr>,
    pub s_q: Box<Fr>,
    pub s_tickets: Box<Vec<Box<Fr>>>,
    pub s_y_dash: Box<Fr>
}



pub fn do_pairing(g_1: &G1Affine,g_2: &G2Affine) -> Fq12{
    Bls12::final_exponentiation(&Bls12::miller_loop([
        &(&(*g_1).prepare(), &(*g_2).prepare())])).unwrap()
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

pub fn add_fr_fr(a: Fr, b: & Fr) -> Fr {
    let mut r = &mut a.clone();
    r.add_assign(b);
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
pub fn fr_neg(a: Fr) -> Fr{
    let mut r =a.clone(); 
    r.negate();
    r
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

pub fn print_fr(a: &Fr) -> (){
    println!("element fr:{:?}",*a);
    println!();
}

pub fn print_g1(a: &G1) -> (){
    println!("element g1:{:?}",a.into_affine());
    println!();
}

pub fn print_g2(a: &G2) -> (){
    println!("element g2:{:?}",a.into_affine());
    println!();
}
pub fn print_gt(a: &Fq12) -> (){
    println!("element gt:{:?}",*a);
    println!();
}

pub fn convert_to_bits(bytes: &[u8]) -> BitVec {
    let mut bits = BitVec::new();
    for &byte in bytes {
        for i in 0..8 {
            bits.push((byte >> (7 - i)) & 1 == 1);
        }
    }
    bits
}

// Function to convert Fq element to bytes
pub fn fq_to_bytes(fq: &Fq) -> Vec<u8> {
    let fq_repr = fq.into_repr();
    let mut bytes = vec![0u8; fq_repr.as_ref().len() * 8];
    fq_repr.write_le(&mut bytes[..]).unwrap();
    bytes
}


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

pub fn gen_cm_c(a: &G1) -> Fr{
    let mut combined_bits = BitVec::new();
    combined_bits.extend(g1_to_bits(a));

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

    let mut repr = [0u64; 4];
    for (i, chunk) in hash_result.chunks(8).enumerate() {
        repr[i] = u64::from_le_bytes(chunk.try_into().expect("Chunk should be 8 bytes long"));
    }
    
    let mut combined_fr = Fr::zero();
    for &value in repr.iter() {
        let fr_repr = FrRepr::from(value);
        let fr_value = Fr::from_repr(fr_repr).expect("Value is not a valid field element");

        combined_fr.add_assign(&fr_value);
    }
    combined_fr

}

pub fn gen_bbs_sig_c(A1: &G1, A2: &G1, T1: &G1,
                     T2: &G1, R_x: &G1, R_s: &G1, R_t: &Vec<G1>, R: &Fq12) -> Fr{

        let mut combined_bits = BitVec::new();
        combined_bits.extend(g1_to_bits(A1));
        combined_bits.extend(g1_to_bits(A2));
        combined_bits.extend(g1_to_bits(T1));
        combined_bits.extend(g1_to_bits(T2));
        combined_bits.extend(g1_to_bits(R_x));
        combined_bits.extend(g1_to_bits(R_s));

        let size = R_t.len();
        for i in 0..size{
            combined_bits.extend(g1_to_bits(&R_t[usize::try_from(i).unwrap()]));
        }

        combined_bits.extend(fq12_to_bits(R));

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