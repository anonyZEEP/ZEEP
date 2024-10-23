extern crate pairing;
extern crate rand;
extern crate blake2;
extern crate byteorder;
use crate::util;

use byteorder::{ReadBytesExt, BigEndian,ByteOrder, NativeEndian};
use rand::{SeedableRng, Rng, Rand,XorShiftRng};
use rand::chacha::ChaChaRng;
use pairing::bls12_381::*;
use pairing::*;
use blake2::{Blake2b, Digest, Blake2s};
use std::borrow::BorrowMut;
use std::convert::TryInto;
use std::fmt;
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct boneh_boyen{
    pk: Box<G2>,
    sk: Box<Fr>,
    g1: Box<G1>,
    g2: Box<G2>
}

// pub struct set_mem_zkp{
    
// }
impl boneh_boyen{
    pub fn Setup() -> boneh_boyen{

        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let mut rr = boneh_boyen{
            sk: Box::new(util::gen_random_fr(rng.borrow_mut())),
            pk: Box::new(util::gen_random_g2(rng.borrow_mut())),
            g1: Box::new(G1::one()),
            g2: Box::new(G2::one())
        };
        rr.pk = Box::new(util::mul_g2_fr(G2::one(), &rr.sk));
        rr
    }
    pub fn Sign(&self, t: &Fr) -> G1{
        let inv = util::fr_inv(util::add_fr_fr(*self.sk, &t));
        let sig = util::mul_g1_fr(G1::one(), &inv);
        sig
    }

    pub fn print_val(&self){
        println!("This is sk: ");
        util::print_fr(&self.sk);

        println!("This is pk: ");
        util::print_g2(&self.pk);

        println!("This is g1: ");
        util::print_g1(&self.g1);

        println!("This is g2: ");
        util::print_g2(&self.g2);
    }
    // pub fn Create_ZKP() -> set_mem_zkp {

    // }
}