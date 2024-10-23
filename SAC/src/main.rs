extern crate pairing;
extern crate rand;
extern crate blake2;
extern crate byteorder;
mod util;
mod bbs;
mod bb;
mod sp;
mod user;

use byteorder::{ReadBytesExt, BigEndian,ByteOrder, NativeEndian};
use rand::{SeedableRng, Rng, Rand,XorShiftRng};
use rand::chacha::ChaChaRng;
use pairing::bls12_381::*;
use pairing::*;
use blake2::{Blake2b, Digest, Blake2s};
use std::borrow::{Borrow, BorrowMut};
use std::fmt;
use std::time::{Duration, Instant};

use crate::util::mul_g1_fr;

fn main(){


    let mut k = sp::SP::Setup(5);
    let mut uu = user::User::Setup(&k);

    let s = Fr::from_str(&5.to_string()).unwrap();

    println!("{:?}", *uu.cred);

    let (Cm, y_dash) = uu.Prepare_Cred(&s, &k);

    // println!(" ");
    // println!("{:?}", *uu.cred);

    //let rrr = *uu.cred.x;

    let (Cm2, x_dash) = k.send_x_dash(&Cm);

    //let Cm_dash = util::mul_g1_fr(*k.bbs_ticket.gen_g1[1], &util::add_fr_fr(rrr, &x_dash));

    let zkp = uu.combine_x_dash(x_dash.clone(), y_dash.clone(), &k);

    //assert_eq!(*Cm2, Cm_dash);
    
    let mut r = k.sign_and_verify(&zkp, &Cm2);

    r.print_val();

    let t = uu.verify_and_store_cred(&k, &Cm2, &mut Box::new(r), y_dash.clone());

    println!("{:?}", t);

    let g: (usize, usize, Box<Vec<usize>>, Fr) = uu.reg_start(&k);

    let t = k.send_ticket(g.0.clone(), g.1.clone(), g.3.clone());
    

    // let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
    // let r = util::gen_random_fr(rng.borrow_mut());
    // let x = util::gen_random_fr(rng.borrow_mut());
    // let c = util::gen_random_fr(rng.borrow_mut());

    // let s_q = util::add_fr_fr(r, &util::mul_fr_fr(x, &c));

    // let Cma = util::mul_g1_fr(*k.bbs_ticket.gen_g1[1], &x);
    // let Cm_dash = util::mul_g1_fr(*k.bbs_ticket.gen_g1[1], &r);
    // let mut cmm = util::mul_g1_fr(*k.bbs_ticket.gen_g1[1], &s_q);
    // cmm = util::add_g1_g1(cmm, util::mul_g1_fr(Cma, &util::fr_neg(c)));

    // util::print_g1(&Cm_dash);
    // util::print_g1(&);
    // assert_eq!(cmm, Cm_dash);






    // println!("{:?} ", (*k).bbs_ticket.gen_g1.len());

    // let hh = Fr::from_str(&5.to_string()).unwrap();
    
    // let mut gg: (Box<user::credential>, Box<G1>, Fr) = user::User::Prepare_Cred(&hh,k.clone());

    // let kk = sp::SP::send_x_dash(gg.1.clone(), k.clone());
    // let zkp = user::User::combine_x_dash(gg.0.clone(), k.clone(),kk.1.clone(),gg.2.clone());

    // let sig = sp::SP::send_sig(zkp.clone(), k.clone(), gg.1.clone());

    // //gg.2 = util::add_fr_fr(gg.2.clone(), &sig.y);

    // user::User::verify_and_store_cred(gg.0.clone(), k.clone(), kk.0.clone(), sig.clone(), gg.2.clone());

    // let toke = user::User::reg_start(gg.0.clone(), k.clone());



    //sp::SP::print_val(&k);
    // let y = bbs::BBS::Setup(5);
    // BBS::print_val(&y);



    // let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
    // let mut a: Vec<Fr> = Vec::new();
    // for i in 0..5 {
    //     a.push(util::gen_random_fr(rng.borrow_mut()));
    // }

    // let si: bbs_sign = BBS::Sign(&y, &a);


    // // let p  = util::gen_random_fr(rng.borrow_mut());
    // // let pai1 = util::do_pairing(&G1::one().into_affine(), &G2::one().into_affine());
    // // let pai2 = util::do_pairing(&util::mul_g1_fr(G1::one(),&p).into_affine(),&util::mul_g2_fr(G2::one(),&util::fr_inv(p)).into_affine());
    
    // // println!("{:?}",pai1);
    // // println!("{:?}",pai2);
    // // assert_eq!(pai1, pai2);
    // BBS::Verify(&y, &a, &si);

    // let a = 0;
    // let mut one = Fr::from_str(&a.to_string()).unwrap();
    // util::print_fr(&one);
    // let mut neg = one.clone();
    // println!("{:?}",one);
    // neg.negate();
    
    // println!("{:?}",neg);

    // let r = util::add_fr_fr(one, &neg);

    // util::print_fr(&r);
    // let p  = Fr::one() Fr::negate(&mut self);
    // util::print_fr(&p);

    // let kkk = util::fr_inv(p);

    // util::print_fr(&kkk);

    // let y = util::mul_fr_fr(p, &kkk);

    //util::print_fr(&y);

    // let x = util::gen_random_fr(rng.borrow_mut());
    // let y1 = util::gen_random_fr(rng.borrow_mut());
    // let y2 = util::gen_random_fr(rng.borrow_mut());
    // let g1 = G1::one();
    // let g2 = G2::one();

    // util::print_fr(&x);
    // util::print_fr(&y1);
    // util::print_fr(&y2);
    // util::print_g1(&g1);
    // util::print_g2(&g2);

    // let X = util::mul_g2_fr(g2, &x);
    // let Y1 = util::mul_g2_fr(g2, &y1);
    // let Y2 = util::mul_g2_fr(g2, &y2);

    // util::print_g2(&X);
    // util::print_g2(&Y1);
    // util::print_g2(&Y2);


    // let m = util::gen_random_fr(rng.borrow_mut());
    // let m_dash = util::gen_random_fr(rng.borrow_mut());
    // let h = util::gen_random_g1(rng.borrow_mut());

    // util::print_fr(&m);
    // util::print_fr(&m_dash);
    // util::print_g1(&h);

    // let r = util::add_fr_fr(util::add_fr_fr(x, &util::mul_fr_fr(y1, &m)), &util::mul_fr_fr(y2, &m_dash));
    
    // util::print_fr(&r);

    // let sig_2 = util::mul_g1_fr(h, &r);

    // util::print_g1(&sig_2);

    // let uu = util::add_g2_g2(X, util::add_g2_g2(util::mul_g2_fr(Y1, &m), util::mul_g2_fr(Y2, &m_dash)));

    // util::print_g2(&uu);

    // let pair = util::do_pairing(&h.into_affine(), &uu.into_affine());

    // util::print_gt(&pair);
    // let pair2 = util::do_pairing(&sig_2.into_affine(), &g2.into_affine());

    // util::print_gt(&pair2);

    // assert_eq!(pair, pair2);


    // let sk2 = util::gen_random_g1(rng.borrow_mut());
    // let sk3 = util::gen_random_g2(rng.borrow_mut());
    // let sk4 = util::gen_random_gt(rng.borrow_mut());


    // println!("sk:{:?}",sk);
    // println!();
    // println!("sk:{:?}",sk2);
    // println!();
    // println!("sk:{:?}",sk3);
    // println!();
    // println!("sk:{:?}",sk4);
    // sk2.mul_assign(sk);
    // assert_eq!(sk3, sk2);
    
    // let mut g1 = G1Affine::one();//g1
    // let mut g2 = G2Affine::one();
    // let sig = g1.mul(sk);
    // let sig2 = g2.mul(sk);

    // let pp3 = util::do_pairing(&g1, &sig2.into_affine());
    
    // let pp4 = Bls12::final_exponentiation(&Bls12::miller_loop([
    //     &(&sig.into_affine().prepare(), &g2.prepare())])).unwrap();
    // println!("sk:{:?}",pp3);
    // println!("dghbj:{:?}", pp4);
    // assert_eq!(pp3,pp4);
}