extern crate aes_gcm_siv;
extern crate pairing;
extern crate rand;
extern crate sha2;

use crate::{
    util::{
        add_fr_fr, gen_random_fr, get_random_rng, int_to_fr,IAPublicKey, IASecretKey, PS_pk, PS_sk
    }, Accumulator::{self, nonmem_create, zkp_non_mem_ver}, DGSA, MPEREA::zkp_sign_q_verify, PS::{self, sign}
};
use pairing::{bls12_381::*, CurveProjective, Field};
use rand:: XorShiftRng;
use std::collections::HashMap;

pub struct IA {
    IASecretKey: IASecretKey,
    pub IAPublicKey: IAPublicKey,
    a_sk: Fr,
    pub a_pk: G2,
    ps_sk: PS_sk,
    pub ps_pk: PS_pk,
    pub set_i: HashMap<(u128, u128), Fr>,
    pub block_list: Vec<Fr>,
    issued_list: Vec<Fr>,
    ticket_list: Vec<Fr>,
    pub def_t: Fr,
    pub vt: G1
}

impl IA {
    // Constructor for EA that initializes sk and pk to default values
    pub fn new() -> Self {
        IA {
            IASecretKey: IASecretKey {
                sk_x2: Fr::zero(),
                sk_id: Fr::zero(),
                sk_epoch: Fr::zero(),
                sk_k1: Fr::zero(),
            },
            IAPublicKey: IAPublicKey {
                pk_X2: G2::zero(),
                pk_id: G2::zero(),
                pk_epoch: G2::zero(),
                pk_K1: G2::zero(),
                g2: G2::zero(),
            },
            a_sk: Fr::zero(),
            a_pk: G2::zero(),
            ps_sk: PS_sk{
                X: G1::zero()
            },
            ps_pk: PS_pk{
                g: G1::zero(),
                g_dash: G2::zero(),
                Y: Vec::new(),
                X_dash: G2::zero(),
                Y_dash: Vec::new(),
            },
            set_i: HashMap::new(),
            block_list: Vec::new(),
            issued_list: Vec::new(),
            ticket_list: Vec::new(),
            def_t: Fr::zero(),
            vt: G1::one()
            
        }
    }

    // Key generation function for EA
    pub fn IA_key_gen(&mut self, mut rng: &mut XorShiftRng, k: u64) {
        // Generate a random secret key
        //let attribute = 1;
        let (sk_x2, sk_id, sk_epoch, sk_k1, pk_X2, pk_id, pk_epoch, pk_K1, g2) =
            DGSA::keygen(&mut rng);
        let mut set_i: HashMap<(u128, u128), Fr> = HashMap::new();

        self.IASecretKey = IASecretKey {
            sk_x2,
            sk_id,
            sk_epoch,
            sk_k1,
        };
        self.IAPublicKey = IAPublicKey {
            pk_X2,
            pk_id,
            pk_epoch,
            pk_K1,
            g2,
        };
        self.set_i = set_i;
        let a_key = Accumulator::keygen(rng);
        self.a_sk = a_key.1;
        self.a_pk = a_key.0;
        self.def_t = gen_random_fr(&mut get_random_rng());
        let (sk, pk) = PS::ps_keygen(rng, k);
        self.ps_sk = sk;
        self.ps_pk = pk;
    }

    pub fn fill_bl(&mut self, k: u64){
        for _ in 0..k{
            self.block_list.push(gen_random_fr(&mut get_random_rng()));
        }
        for &x in &self.block_list {
            self.vt = Accumulator::add(self.a_sk, self.vt, x);
        }
    }

    pub fn register_user_i(
        &mut self,
        commit_pie: &(G1, (Fr, Fr, Vec<Fr>), Fr),
        epoch: Fr,
        k: u64,
        g: G1,
        q_hat: Fr,
        vid: Fr
    ) -> Option<((G1, G1, G1), (G1, Fr))> {
        let (commit, pie_r, r) = commit_pie;
        let sigma_star = sign(pie_r, commit, epoch, &self.ps_sk, &self.ps_pk, k);
        
        if(sigma_star == None){
            println!("Not Verify at registration IA\n");
            None
        }else{
            let wt = nonmem_create(self.a_sk, &self.block_list, q_hat, g);
            self.issued_list.push(vid);
            Some((sigma_star.unwrap(), wt))
        }
    
    }
    pub fn authenticate_user_i(
        &mut self,
        req: &(Fr, Fr, (G1, G1), (Fr, (Fr, Fr, Fr, Fr, Fr), G1, G1, G1, G1, Fq12, Fr), (G1, (Fr, Fr, Vec<Fr>), Fr), Fr),
        e_j: Fr,
        k: u64,
        g: G1,
        zkp_non: Vec<(Fr, Fr, Fr, Fr, Fr, Fr, Fr, G2, G1, G1, G2, G1, G2, G2, Fq12)>
    ) -> Option<((G1, G1, G1), (G1, Fr))> {
        let e_j_1 = add_fr_fr(e_j, &int_to_fr(&1));
        let zkpok_ch = zkp_sign_q_verify(&self.ps_pk, req.1, req.3, req.0);
        let g2 = G2::one();
        let mut ch = false;
        for zkp_wt in zkp_non{
            ch = zkp_non_mem_ver(zkp_wt, g, g2, self.vt);
        }
        let sigma_star = sign(&req.4.1, &req.4.0, e_j_1, &self.ps_sk, &self.ps_pk, k);
        if(sigma_star == None){
            println!("wt_ver: {}", zkpok_ch);
            println!("Not Verify at authenticate IA\n");
            None
        }else{
            let wt = nonmem_create(self.a_sk, &self.block_list, req.0, g);
            Some((sigma_star.unwrap(), wt))
        }
    
    }

    pub fn compute_sigma(
        &mut self,
        mut rng: &mut XorShiftRng,
        vid: u128,
        epoch: u128,
    ) -> Option<(Fr, G1, G1)> {
        if let Some(((a_dash, h, sigma_2), updated_set)) =
            DGSA::issue_i(rng, &self.IASecretKey, &vid, &epoch, &mut self.set_i)
        {
            self.set_i = updated_set.clone();
            let sigma = (a_dash.clone(), h.clone(), sigma_2.clone());
            println!("DGSA Issuance Successful");
            Some(sigma)
        } else {
            println!("DGSA Issuance Failed: Key (id, epoch) is present in the map");
            None
        }
    }
}
