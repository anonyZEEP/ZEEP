extern crate pairing;
extern crate rand;
extern crate blake2;
extern crate byteorder;
use crate::util;

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
pub struct BBS{
    pub k: u32,
    sk: Box<Fr>,
    pub pk: Box<G2>,
    pub gen_g1: Box<Vec<Box<G1>>>,
    pub gen_g2: Box<G2>,
}

impl BBS{
    pub fn Setup(k: u32) -> BBS{
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let mut rr = BBS{
            k: k,
            gen_g1: Box::new(Vec::new()),
            gen_g2: Box::new(util::gen_random_g2(rng.borrow_mut())),
            sk: Box::new(util::gen_random_fr(rng.borrow_mut())),
            pk: Box::new(util::gen_random_g2(rng.borrow_mut()))
        };
        for n in 0..(rr.k+4) {
            rr.gen_g1.push(Box::new(util::gen_random_g1(rng.borrow_mut())))
        }
        rr.pk = Box::new(util::mul_g2_fr(*rr.gen_g2, &rr.sk));
        rr
    }
    pub fn Sign(&self, msg: Box<Vec<Fr>>) -> util::bbs_sign{
        let length: u32 = msg.len() as u32;
        assert_eq!(length, self.k);

        
        let mut h0 = *self.gen_g1[0].as_ref();

        for (i,ele) in msg.into_iter().enumerate(){
            h0 = util::add_g1_g1(h0, util::mul_g1_fr(*self.gen_g1[i+1],&ele));
        }
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let e = util::gen_random_fr(rng.borrow_mut());
        let y = util::gen_random_fr(rng.borrow_mut());

        let length2 = self.gen_g1.len();
        h0 = util::add_g1_g1(h0, util::mul_g1_fr(*self.gen_g1[length2-1],&y));

        // println!("This is h0");
        // util::print_g1(&h0);

        let A = util::mul_g1_fr(h0, &util::fr_inv(util::add_fr_fr(e, &self.sk)));

        util::bbs_sign{
            A: Box::new(A),
            e: Box::new(e),
            y: Box::new(y)
        }

    }

    pub fn Verify(&self, msg: &Vec<Fr>, sig: &util::bbs_sign){
        let length: u32 = msg.len() as u32;
        assert_eq!(length, self.k);

        let mut h0 = *self.gen_g1[0].as_ref();

        for (i,ele) in msg.into_iter().enumerate(){
            //println!("{}",i);
            h0 = util::add_g1_g1(h0, util::mul_g1_fr(*self.gen_g1[i+1],&ele));
        }
        let length2 = self.gen_g1.len();
        h0 = util::add_g1_g1(h0, util::mul_g1_fr(*self.gen_g1[length2-1],&sig.y));
        
        println!("This is h0");
        util::print_g1(&h0);

        let wfe = util::add_g2_g2(*self.pk, util::mul_g2_fr(*self.gen_g2, &sig.e));

        let pair1 = util::do_pairing(&sig.A.into_affine(), &wfe.into_affine());
        let pair2 = util::do_pairing(&h0.into_affine(), &self.gen_g2.into_affine());

        assert_eq!(pair1, pair2);
    }
    pub fn Sign_commitment(&self, comm: &G1) -> util::bbs_sign{
        
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let e = util::gen_random_fr(rng.borrow_mut());
        let y = util::gen_random_fr(rng.borrow_mut());
        
        let h0 = util::add_g1_g1(*self.gen_g1[0], util::add_g1_g1(*comm, util::mul_g1_fr(*self.gen_g1[self.gen_g1.len()-1], &y)));
        let A = util::mul_g1_fr(h0, &util::fr_inv(util::add_fr_fr(*self.sk, &e)));

        util::bbs_sign{
            A: Box::new(A),
            e: Box::new(e),
            y: Box::new(y)
        }
    }
    pub fn Verify_sign_commitment(self: &BBS, comm: &G1, sig: &util::bbs_sign) -> bool{

        let mut h0 = *self.gen_g1[0].as_ref();

        let wfe = util::add_g2_g2(*self.pk, util::mul_g2_fr(*self.gen_g2, &sig.e));
        
        let first = util::add_g1_g1(*self.gen_g1[0], util::add_g1_g1(*comm, util::mul_g1_fr(*self.gen_g1[self.gen_g1.len()-1], &sig.y)));
        
        let pair1 = util::do_pairing(&sig.A.into_affine(), &wfe.into_affine());
        let pair2 = util::do_pairing(&first.into_affine(), &self.gen_g2.into_affine());

        assert_eq!(pair1, pair2);
        return pair1 == pair2;

    }
    // pub fn Create_ZKP(pp: &BBS, sig: &util::bbs_sign) -> util::bbs_zkp{
    //     let A = sig.A;
    //     let e = sig.e;
    //     let y = sig.y;
        
    //     let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        
    //     let r_A = util::gen_random_fr(rng.borrow_mut());
    //     let r_t = util::gen_random_fr(rng.borrow_mut());
    //     let r_e = util::gen_random_fr(rng.borrow_mut());
    //     let r_beta = util::gen_random_fr(rng.borrow_mut());
    //     let r_x = util::gen_random_fr(rng.borrow_mut());
    //     let r_s = util::gen_random_fr(rng.borrow_mut());

    //     let mut r: Vec<Fr> = Vec::new();

    //     for (itr, val) in 0..pp.k.clone(){
    //         let ran = util::gen_random_fr(rng.borrow_mut());
    //         r.push(ran);
    //     }

    //     let B = util::mul_fr_fr(r_A, &e);
    //     let A1 = util::add_g1_g1(A, util::mul_g1_fr(pp.gen_g1[0], &r_A));
    //     let A2  = util::mul_g1_fr(pp.gen_g1[1], &r_A);
    //     let T1 = util::mul_g1_fr(pp.gen_g1[1], &r_t);
    //     let T2 = util::add_g1_g1(util::mul_g1_fr(A2, &util::fr_neg(r_e)), util::mul_g1_fr(pp.gen_g1[1], &r_beta));
    //     let R_x = util::mul_g1_fr(G1::one(), &r_x);
    //     let R_s = util::mul_g1_fr(G1::one(), &r_s);
        
    //     let R_t = Vec::new();
    //     for (i, val) in r.clone().into_iter().enumerate() {
    //         R_t.push(util::mul_g1_fr(G1::one(), &val));            
    //     }

    //     let R = util::do_pairing(pp.gen_g1[1].into_affine(), util::mul_g2_fr(pp.gen_g2, &r_x).into_affine());
    //     R = util::mul_fq12_fq12(R, util::do_pairing(pp.gen_g1[3].into_affine(), util::mul_g2_fr(pp.gen_g2, &r_s).into_affine()));
    //     R = util::mul_fq12_fq12(R, util::do_pairing(pp.gen_g1[pp.k + 4].into_affine(), util::mul_g2_fr(pp.gen_g2, &r_y).into_affine()));
        


    // }
    // pub fn Verify_ZKP(pp: &BBS, zkp: &bbs_zkp){

    // }
    // pub fn print_val(p: &Self){
    //     println!("This is k: {}", p.k);
        
    //     println!("This is sk: ");
    //     util::print_fr(&p.sk);

    //     println!("This is pk: ");
    //     util::print_g2(&p.pk);

    //     println!("This is generator g1: ");
    //     for (index, element) in p.gen_g1.iter().enumerate() {
    //         util::print_g1(&element);
    //     }
    //     println!("This is generator g2: ");
    //     util::print_g2(&p.gen_g2);
    // }


}