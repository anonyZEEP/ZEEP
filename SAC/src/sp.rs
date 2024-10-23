extern crate pairing;
extern crate rand;
extern crate blake2;
extern crate byteorder;

use crate::bbs;
use crate::bbs::BBS;
use crate::user;
use crate::util;
use crate::bb;
use crate::util::randoms;

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
use std::convert::TryFrom;

#[derive(Clone, Debug)]
pub struct SP{
   pub k_max: u32,
   pub bbs_ticket: Box<bbs::BBS>,
   pub bbs_score: Box<bbs::BBS>,
   pub bb: Box<bb::boneh_boyen>,
   pub session_list: Box<Vec<Box<util::session>>>,
   pub score_sig: Box<Vec<Box<G1>>>,
   pub curr_session: Box<util::curr_sess>
}

impl SP{

    pub fn Setup(size: u32) -> Box<SP>{
        let rr = Box::new(bbs::BBS::Setup(size));
        let gg = Box::new(bbs::BBS::Setup(2));
        let aa = Box::new(bb::boneh_boyen::Setup());

        let mut y = Box::new(SP{
            k_max: size.clone(),
            bbs_ticket: rr.clone(),
            bbs_score: gg.clone(),
            bb: aa.clone(),
            session_list: Box::new(Vec::new()),
            score_sig: Box::new(Vec::new()),
            curr_session: Box::new(util::curr_sess::default())
        });
        for i in 1..15{
            y.score_sig.push(Box::new(aa.Sign(&Fr::from_str(&i.to_string()).unwrap())));
        }

        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        for j in 0..size {
            let idd = util::gen_random_fr(rng.borrow_mut());
            let scoore  = Fr::from_str(&0.to_string()).unwrap();
            let mut vecc = Box::new(Vec::new());
            vecc.push(idd);
            vecc.push(scoore);
            let bbbs_sig = Box::new((*y.bbs_score).Sign(vecc));
            let bbb_sig = aa.Sign(&scoore);
            let mut h = Box::new(util::session{
                id: idd,
                score: scoore,
                bbs_sig: bbbs_sig,
                bb_sig: bbb_sig,
                status: util::ticket_status::DEFAULT
            });
            y.session_list.push(h);
        }
        y

    }

    pub fn send_x_dash(&mut self, Cm: &Box<G1>) -> (Box<G1>, Fr){
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let x_dash = util::gen_random_fr(rng.borrow_mut());

        let mut Cm_dash = *(*Cm).clone();
        Cm_dash = util::add_g1_g1(Cm_dash, util::mul_g1_fr(*self.bbs_ticket.gen_g1[1], &x_dash));

        return (Box::new(Cm_dash), x_dash);
    }

    pub fn verify_reg_zkp(&mut self, zkp: &Box<util::P_iss_ZKP>, cm: &Box<G1>) -> bool{

            let mut cm_dash = util::add_g1_g1(util::mul_g1_fr(*self.bbs_ticket.gen_g1[1], &(*zkp).s_x), util::mul_g1_fr(*self.bbs_ticket.gen_g1[2], &(*zkp).s_q));
            for i in 0..self.k_max {
                cm_dash = util::add_g1_g1(cm_dash, util::mul_g1_fr(*self.bbs_ticket.gen_g1[usize::try_from(i).unwrap()+4], &(*zkp).s_tickets[usize::try_from(i).unwrap()]));
            }
            cm_dash = util::add_g1_g1(cm_dash, util::mul_g1_fr(*self.bbs_ticket.gen_g1[self.bbs_ticket.gen_g1.len() - 1], &zkp.s_y_dash));
            cm_dash = util::add_g1_g1(cm_dash, util::mul_g1_fr(*(*cm), &util::fr_neg(*zkp.challenge)));
            
            println!("This is Cm_dash ");
            util::print_g1(&cm_dash);
            let chall = util::gen_cm_c(&cm_dash);
            util::print_fr(&chall);
            
            return *zkp.challenge == chall;
    }
    pub fn sign_and_verify(&mut self, zkp: &Box<util::P_iss_ZKP>, cm: &Box<G1>) -> util::bbs_sign{

        if self.verify_reg_zkp(zkp, cm){
            return self.bbs_ticket.Sign_commitment(cm);
        }
        else{
            return util::bbs_sign::default();
        }
    }

    pub fn send_ticket(&mut self,k: usize, m: usize, q: Fr) -> (Fr, Box<util::randoms>) {
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let t = util::gen_random_fr(rng.borrow_mut());

        self.curr_session = Box::new(util::curr_sess{
            K: k.clone(),
            M: m.clone(),
            q: q.clone()
        });
        let mut deltai = Vec::new();
        let mut lambdai = Vec::new();
        let mut gammai = Vec::new();
        let mut thetai = Vec::new();

        for i in 0..k {
            deltai.push(util::gen_random_fr(&mut rng));
        }
        for i in 0..(self.curr_session.K - self.curr_session.M) {
            lambdai.push(util::gen_random_fr(&mut rng));
            gammai.push(util::gen_random_fr(&mut rng));
        }
        
        for i in 0..(self.curr_session.M) {
            thetai.push(util::gen_random_fr(&mut rng));
        }
        let ran = util::randoms{
            delta_i: Box::new(deltai),
            lambda_i: Box::new(lambdai),
            gamma_i: Box::new(gammai),
            theta_i: Box::new(thetai)
        };
        return (t, Box::new(ran));

    }

    // pub fn verify_zkp(zkp: Box<user::P_iss_ZKP>, sp: Box<SP>, Cm: Box<G1>) -> bool{

    //     let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    //     let chal = zkp.challenge;

    //     let h_list = sp.bbs_ticket.gen_g1.as_ref();

    //     let mut Cm_dash = Box::new(util::add_g1_g1(util::mul_g1_fr(*h_list[0], &zkp.s_x), util::mul_g1_fr(*h_list[1], &zkp.s_q)));
    //     *Cm_dash = util::add_g1_g1(*Cm_dash, util::mul_g1_fr(*h_list[2],&zkp.s_sc));
        
    //     for i in 0..(*zkp).s_tickets.len() {
    //         *Cm_dash = util::add_g1_g1(*Cm_dash, util::mul_g1_fr(*h_list[i+3], &zkp.s_tickets[i]));
    //     }

    //     *Cm_dash = util::add_g1_g1(*Cm_dash, util::mul_g1_fr(*h_list[h_list.len()-1], &zkp.s_y_dash));



    //     let cm_dash = util::add_g1_g1(util::mul_g1_fr(*Cm, &chal), *Cm_dash);

    //     let challenge = util::gen_random_fr(rng.borrow_mut()); // change this

    //     return challenge == chal;
    
    // }

    // pub fn print_val(pp: &SP){
    //     println!("This is k in SP: {}", pp.k_max);

    //     bbs::BBS::print_val(&pp.bbs_ticket);
    //     bbs::BBS::print_val(&pp.bbs_score);
    //     bb::boneh_boyen::print_val(&pp.bb);

    //     println!("This is session list");
    //     for (i,ele) in pp.session_list.clone().into_iter().enumerate() {

    //         session::print_val(&ele);
    //     }


    // }

    // pub fn Register(){

    // }
    // pub fn Authenticate(){

    // }
    
}