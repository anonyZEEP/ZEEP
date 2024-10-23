extern crate pairing;
extern crate rand;
extern crate blake2;
extern crate byteorder;

use crate::bbs;
use crate::util;
use crate::bb;
use crate::sp;
use crate::util::bbs_zkp;

use byteorder::{ReadBytesExt, BigEndian,ByteOrder, NativeEndian};
use rand::{SeedableRng, Rng, Rand,XorShiftRng};
use rand::chacha::ChaChaRng;
use pairing::bls12_381::*;
use pairing::*;
use blake2::{Blake2b, Digest, Blake2s};
use std::borrow::BorrowMut;
use std::convert::TryFrom;
use std::fmt;
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct User{
    pub k: u32,
    pub serv: Box<sp::SP>,
    pub cred: Box<util::credential>,
    pub sig: Box<util::bbs_sign>
}

impl User{

    pub fn Setup(se: &Box<sp::SP>) -> Box<User>{
        
        Box::new(User { k: se.k_max, serv: (*se).clone(), cred:  Box::new(util::credential::default()), sig: Box::new(util::bbs_sign::default())})
    }

    pub fn Prepare_Cred(&mut self,size: &Fr, service_provider: &Box<sp::SP>) -> (Box<G1>, Fr){
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        
        let x_dash = util::gen_random_fr(rng.borrow_mut());
        
        let q = util::gen_random_fr(rng.borrow_mut());

        let scoree = Fr::from_str(&0.to_string()).unwrap();

        let mut cred = Box::new(util::credential{
            x: Box::new(x_dash),
            q: Box::new(q),
            score: Box::new(scoree),
            tickets: Box::new(Vec::new())
        });

        let sess_list = (*service_provider).clone().session_list.clone();

        for (i, ele) in sess_list.into_iter().enumerate()  {
            cred.tickets.push(Box::new(ele.id));
        }

        let y_dash = util::gen_random_fr(rng.borrow_mut());

        let h_list = & *service_provider.bbs_ticket.gen_g1;
        let mut Cm_dash = Box::new(util::add_g1_g1(util::mul_g1_fr(*h_list[1], &cred.x),util::mul_g1_fr(*h_list[2], &cred.q)));


        for i in 0..(*cred).tickets.len() {
            *Cm_dash = util::add_g1_g1(*Cm_dash, util::mul_g1_fr(*h_list[i+4], (*cred).tickets[i].as_ref()));
        }

        *Cm_dash = util::add_g1_g1(*Cm_dash, util::mul_g1_fr(*h_list[h_list.len()-1], &y_dash));

        self.cred = cred;

        return (Cm_dash, y_dash);

    }
    pub fn combine_x_dash(&mut self, x_dash: Fr, y_dash: Fr, sp: &Box<sp::SP>) -> Box<util::P_iss_ZKP>{
            println!("old x");
            util::print_fr(&self.cred.x);
            self.cred.x = Box::new(util::add_fr_fr(*self.cred.x,&x_dash));
            
            println!("new x");
            util::print_fr(&self.cred.x);

            let ZKP = self.create_reg_zkp(sp, y_dash.clone());
            ZKP

    }
    pub fn create_reg_zkp(&mut self, service_provider: &Box<sp::SP>, y_dash: Fr) -> (Box<util::P_iss_ZKP>){
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let r_x = util::gen_random_fr(rng.borrow_mut());
        let r_q = util::gen_random_fr(rng.borrow_mut());

        let h_list = (*service_provider).bbs_ticket.gen_g1.as_ref();

        let mut Cm_dash = Box::new(util::add_g1_g1(util::mul_g1_fr(*h_list[1], &r_x), util::mul_g1_fr(*h_list[2], &r_q)));
        //let Cm_dash = util::add_g1_g1(util::mul_g1_fr(*k.bbs_ticket.gen_g1[1], &uu.cred.x), util::mul_g1_fr(*k.bbs_ticket.gen_g1[2], &uu.cred.q));

        let mut rand_fr = Vec::new();

        for i in 0..(*self.cred).tickets.len() {
            let r_t = util::gen_random_fr(rng.borrow_mut());
            rand_fr.push(r_t);
            *Cm_dash = util::add_g1_g1(*Cm_dash, util::mul_g1_fr(*h_list[i+4], &r_t));
        }
        let r_y_dash = util::gen_random_fr(rng.borrow_mut());

        *Cm_dash = util::add_g1_g1(*Cm_dash, util::mul_g1_fr(*h_list[h_list.len()-1], &r_y_dash));

        println!("This is Cm_dash ");
        util::print_g1(& *Cm_dash);
        let chall = util::gen_cm_c(& *Cm_dash); // replace with actual challenge
        util::print_fr(&chall);

        // println!("new x");
        // util::print_fr(&self.cred.x);
        let mut ans = Box::new(util::P_iss_ZKP{
            challenge: Box::new(chall),
            s_x: Box::new(util::add_fr_fr(r_x, &util::mul_fr_fr(chall, &self.cred.x))),
            s_q: Box::new(util::add_fr_fr(r_q, &util::mul_fr_fr(chall, &self.cred.q))),
            s_tickets: Box::new(Vec::new()),
            s_y_dash: Box::new(util::add_fr_fr(r_y_dash, &util::mul_fr_fr(chall, &y_dash)))
        });

        for i in 0..rand_fr.len(){
            ans.s_tickets.push(Box::new(util::add_fr_fr(rand_fr[i], &util::mul_fr_fr(chall, &self.cred.tickets[i]))));
        }

        return ans;

    }
    pub fn verify_and_store_cred(&mut self, service_provider: &Box<sp::SP>, Cm: &Box<G1>, sig: &mut Box<util::bbs_sign>, y_dash: Fr) -> bool{
            let mut sigg = (*sig).clone();
            *sigg.y = util::add_fr_fr(*sigg.y, &y_dash);
            self.sig = sigg;
            let p = bbs::BBS::Verify_sign_commitment(service_provider.bbs_ticket.as_ref(), &Cm, sig.as_ref());
            assert!(p);
            return p;
    }

    pub fn reg_start(&mut self, sp: &Box<sp::SP>) -> (usize, usize, Box<Vec<usize>>, Fr){
         let tickets = self.cred.tickets.clone();
         
         let judged_vec: Vec<usize> = Vec::new();
         let mut index = Box::new(judged_vec);

         let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
         //let t = util::gen_random_fr(rng.borrow_mut());
         for (i, val) in tickets.into_iter().enumerate(){
                for (j, tick) in (*sp).session_list.clone().into_iter().enumerate(){
                        if *val == tick.id && tick.status == util::ticket_status::JUDGED {
                            index.push(i);
                            break;
                        }
                }
         }

         return (self.cred.tickets.len(), index.len(), index, *(self.cred.q));
    }

    pub fn send_sig_zkp(&mut self, t: Fr, sp: &Box<sp::SP>, ran: &Box<util::randoms>){
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let r_A = util::gen_random_fr(rng.borrow_mut());
        let r_t = util::gen_random_fr(rng.borrow_mut());
        let r_e = util::gen_random_fr(rng.borrow_mut());
        let r_B = util::gen_random_fr(rng.borrow_mut());
        let r_x = util::gen_random_fr(rng.borrow_mut());
        let r_s = util::gen_random_fr(rng.borrow_mut());
        let r_y = util::gen_random_fr(rng.borrow_mut());
        let mut r = Vec::new();

        for i in 0..self.k{
            r.push(util::gen_random_fr(rng.borrow_mut()));
        }
        let B = util::mul_fr_fr(r_A, &self.sig.e);
        let A_1 = util::add_g1_g1(*self.sig.A, util::mul_g1_fr(*(*sp).bbs_ticket.gen_g1[0],&r_A));
        let A_2 = util::mul_g1_fr(*(*sp).bbs_ticket.gen_g1[1],&r_A);
        let T_1 = util::mul_g1_fr(*(*sp).bbs_ticket.gen_g1[1],&r_t);
        let T_2 = util::add_g1_g1(util::mul_g1_fr(A_2, &util::fr_neg(r_e)), util::mul_g1_fr(*(*sp).bbs_ticket.gen_g1[1], &r_B));

        let R_x = util::mul_g1_fr(G1::one(), &r_x);
        let R_s = util::mul_g1_fr(G1::one(), &r_s);
        let mut R_t = Vec::new();

        for i in 0..self.k{
            R_t.push(util::mul_g1_fr(G1::one(), &r[usize::try_from(i).unwrap()]));
        }

        let mut R = util::do_pairing(&(*(*sp).bbs_ticket.gen_g1[1]).into_affine(), &util::mul_g2_fr(*(*sp).bbs_ticket.gen_g2, &r_x).into_affine());
        R  = util::mul_fq12_fq12(R, util::do_pairing(&(*(*sp).bbs_ticket.gen_g1[3]).into_affine(), &util::mul_g2_fr(*(*sp).bbs_ticket.gen_g2, &r_s).into_affine()));
        
        for i in 0..self.k{
            R = util::mul_fq12_fq12(R, util::do_pairing(&(*(*sp).bbs_ticket.gen_g1[usize::try_from(i).unwrap() + 4]).into_affine(), &util::mul_g2_fr(*(*sp).bbs_ticket.gen_g2, &r[usize::try_from(i).unwrap() + 4]).into_affine()));
        }
        R = util::mul_fq12_fq12(R, util::do_pairing(&(*(*sp).bbs_ticket.gen_g1[(*sp).bbs_ticket.gen_g1.len() -1]).into_affine(), &util::mul_g2_fr(*(*sp).bbs_ticket.gen_g2, &r[r.len()-1]).into_affine()));
        R = util::mul_fq12_fq12(R, util::do_pairing(&(*(*sp).bbs_ticket.gen_g1[0]).into_affine(), &util::mul_g2_fr(*(*sp).bbs_ticket.pk, &r_t).into_affine()));
        R = util::mul_fq12_fq12(R, util::do_pairing(&(*(*sp).bbs_ticket.gen_g1[0]).into_affine(), &util::mul_g2_fr(*(*sp).bbs_ticket.pk, &r_B).into_affine()));
        R = util::mul_fq12_fq12(R, util::do_pairing(&(A_1).into_affine(), &util::mul_g2_fr(*(*sp).bbs_ticket.gen_g2, &util::fr_neg(r_e)).into_affine()));
        
        let challenge = util::gen_bbs_sig_c(&A_1, &A_2, &T_1, &T_2, &R_x, &R_s, &R_t, &R);

        let z_x = util::add_fr_fr(r_x, &util::mul_fr_fr(challenge, &self.cred.x));
        let z_s = util::add_fr_fr(r_s, &util::mul_fr_fr(challenge, &self.cred.score));
        let z_A = util::add_fr_fr(r_t, &util::mul_fr_fr(challenge, &r_A));
        let z_e = util::add_fr_fr(r_e, &util::mul_fr_fr(challenge, &self.sig.e));
        let z_B = util::add_fr_fr(r_B, &util::mul_fr_fr(challenge, &B));
        let z_y = util::add_fr_fr(r_y, &util::mul_fr_fr(challenge, &self.sig.y));

        let mut z = Vec::new();
        for i in 0..sp.curr_session.K {
            z.push(util::add_fr_fr(r[i], &util::mul_fr_fr(challenge, &self.cred.tickets[i])));
        }

        let zkp_sig = util::bbs_zkp{
            k: self.k,
            B: Box::new(B),
            A1: Box::new(A_1),
            A2: Box::new(A_2),
            T1: Box::new(T_1),
            T2: Box::new(T_2),
            z_x: Box::new(z_x),
            z_s: Box::new(z_s),
            z_A: Box::new(z_A),
            z_e: Box::new(z_e),
            z_B: Box::new(z_B),
            z_y: Box::new(z_y),
            z: Box::new(z),
            challenge: Box::new(challenge)
        };

        let mut list_sessions = Vec::new();

        for (i, val) in self.cred.tickets.clone().into_iter().enumerate() {
            for (j, val2) in sp.session_list.clone().into_iter().enumerate() {
                if *val == (*val2).id {
                    list_sessions.push(val2);
                    break;
                }
            }
        }

        let mut u_i = Vec::new();
        let mut r_si = Vec::new();
        let mut r_ui = Vec::new();
        let mut r_yi = Vec::new();
        let mut r_ei = Vec::new();
        let mut r_Bi = Vec::new();


        for i in 0..self.k {
            u_i.push(util::gen_random_fr(rng.borrow_mut()));
            r_si.push(util::gen_random_fr(rng.borrow_mut()));
            r_ui.push(util::gen_random_fr(rng.borrow_mut()));
            r_Bi.push(util::gen_random_fr(rng.borrow_mut()));
            r_yi.push(util::gen_random_fr(rng.borrow_mut()));
            r_ei.push(util::gen_random_fr(rng.borrow_mut()));
        
        }

        let mut Beta_i = Vec::new();
        let mut D_i = Vec::new();
        let mut B_i = Vec::new();
        let mut S_i = Vec::new();
        let mut T_i = Vec::new();
        let mut W_i = Vec::new();

        for (i, val) in list_sessions.into_iter().enumerate() {
            Beta_i.push(util::mul_fr_fr(u_i[i], &((*val).bbs_sig.e)));
            D_i.push(util::add_g1_g1(*val.bbs_sig.A, util::mul_g1_fr(*sp.bbs_score.gen_g1[0], &u_i[i])));
            B_i.push(util::mul_g1_fr(*sp.bbs_score.gen_g1[1], &u_i[i]));
            S_i.push(util::mul_g1_fr(G1::one(), &r_si[i]));
            T_i.push(util::mul_g1_fr(*sp.bbs_score.gen_g1[1], &r_ui[i]));
            W_i.push(util::add_g1_g1(util::mul_g1_fr(*B_i.last().unwrap(), &util::fr_neg(r_ei[i])), util::mul_g1_fr(*sp.bbs_score.gen_g1[1], &r_Bi[i])));
        }
        let mut di_ri = util::mul_fr_fr((*ran).delta_i[0], &r[0]);
        let mut di_rsi = util::mul_fr_fr((*ran).delta_i[0], &r_si[0]);
        let mut di_ryi = util::mul_fr_fr((*ran).delta_i[0], &r_yi[0]);
        let mut di_rui = util::mul_fr_fr((*ran).delta_i[0], &r_ui[0]);
        let mut di_rBi = util::mul_fr_fr((*ran).delta_i[0], &r_Bi[0]);
        let mut di_rei = util::mul_fr_fr((*ran).delta_i[0], &r_ei[0]);

        for i in 1..self.k{
            di_ri = util::add_fr_fr(di_ri, &util::mul_fr_fr((*ran).delta_i[usize::try_from(i).unwrap()], &r[usize::try_from(i).unwrap()]));
            di_rsi = util::add_fr_fr(di_rsi, &util::mul_fr_fr((*ran).delta_i[usize::try_from(i).unwrap()], &r_si[usize::try_from(i).unwrap()]));
            di_ryi = util::add_fr_fr(di_ryi, &util::mul_fr_fr((*ran).delta_i[usize::try_from(i).unwrap()], &r_yi[usize::try_from(i).unwrap()]));
            di_rui = util::add_fr_fr(di_rui, &util::mul_fr_fr((*ran).delta_i[usize::try_from(i).unwrap()], &r_ui[usize::try_from(i).unwrap()]));
            di_rBi = util::add_fr_fr(di_rBi, &util::mul_fr_fr((*ran).delta_i[usize::try_from(i).unwrap()], &r_Bi[usize::try_from(i).unwrap()]));
            di_rei = util::add_fr_fr(di_rei, &util::mul_fr_fr((*ran).delta_i[usize::try_from(i).unwrap()], &r_ei[usize::try_from(i).unwrap()]));   
        }
        let mut RL = util::do_pairing(&(*(*sp).bbs_ticket.gen_g1[1]).into_affine(), &util::mul_g2_fr(*(*sp).bbs_ticket.gen_g2, &di_ri).into_affine());

        R = util::mul_fq12_fq12(R, util::do_pairing(&(*(*sp).bbs_ticket.gen_g1[2]).into_affine(), &util::mul_g2_fr(*(*sp).bbs_ticket.gen_g2, &di_rsi).into_affine()));
        R = util::mul_fq12_fq12(R, util::do_pairing(&(*(*sp).bbs_ticket.gen_g1[3]).into_affine(), &util::mul_g2_fr(*(*sp).bbs_ticket.gen_g2, &di_ryi).into_affine()));
        R = util::mul_fq12_fq12(R, util::do_pairing(&(*(*sp).bbs_ticket.gen_g1[0]).into_affine(), &util::mul_g2_fr(*(*sp).bbs_ticket.pk, &di_rui).into_affine()));
        R = util::mul_fq12_fq12(R, util::do_pairing(&(*(*sp).bbs_ticket.gen_g1[0]).into_affine(), &util::mul_g2_fr(*(*sp).bbs_ticket.gen_g2, &di_rBi).into_affine()));
        
        let mut D = D_i[0];
        for i in 1..self.k{
            D = util::add_g1_g1(D, D_i[usize::try_from(i).unwrap()]);
        }
        R = util::mul_fq12_fq12(R, util::do_pairing(&D.into_affine(), &util::mul_g2_fr(*(*sp).bbs_ticket.gen_g2, &util::fr_neg(di_rei)).into_affine()));



        let mut V = (self.serv.score_sig[0]).clone();
        let v = util::gen_random_fr(&mut rng);
        let r_v = util::gen_random_fr(&mut rng);
        let mut summ = util::fr_neg(r_s);
        for i in 0..self.k{
            summ = util::add_fr_fr(summ, &util::fr_neg(r_si[usize::try_from(i).unwrap()]));
        }
        *V = util::mul_g1_fr(*V, &v);

        let mut R_s = util::do_pairing(&G1Affine::one(),&util::mul_g2_fr(*sp.bbs_score.gen_g2, &r_v).into_affine());
        R_s = util::add_fq12_fq12(R_s, util::do_pairing(&(*V).into_affine(), &util::mul_g2_fr(*sp.bbs_score.gen_g2, &summ).into_affine()));
        
        let V_j = Vec::new();
        
        
        // for i in 0..self.k{
        //     s = util::add_fr_fr(s, self.cred.tickets[i].)
        // }


    }
    
}