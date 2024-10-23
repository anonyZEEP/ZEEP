extern crate aes_gcm_siv;
extern crate pairing;
extern crate rand;
extern crate sha2;
use std::collections::VecDeque;
use crate::{
    util::{self, add_fr_fr, fr_to_bytes, gen_random_fr, get_random_rng, int_to_fr, mul_g1_fr, IAPublicKey}, 
    Accumulator::{nonmem_update, ver_nonmem, zkp_non_mem}, DAE, DGSA, IA, MPEREA::{self, zkp_sign_q}, PKE, PS::{self, verify, GenCommitment, Unblind}, SE
};
use aes_gcm_siv::{
    aead::{Aead, NewAead},
    Aes128GcmSiv,
};
use pairing::{bls12_381::*, CurveProjective, Field};
use rand::{Rng, XorShiftRng};
use sha2::digest::{
    consts::U12,
    generic_array::{self, GenericArray},
};
use std::{
    collections::HashMap
};


pub struct Veh {
    pub v_id: u128,
    //v_sk: PS_sk,
    //pub v_pk: PS_pk,
    pub sig_e: G1,
    pub cred_ps: (Fr, (G1, G1), (G1, Fr), G1),
    pub cred: (u128, u128, (Fr, G1, G1)),
    pub pke_ek: G2,
    pke_dk: Fr,
    ticket_q: VecDeque<Fr>,
    bl_size: usize,
    commit_pie: (G1, (Fr, Fr, Vec<Fr>), Fr),
    wt_map: HashMap<Vec<u8>, (G1, Fr)>,
    vt: G1,
    pub q_id: Fr
}

impl Veh {
    // Constructor for EA that initializes sk and pk to default values
    pub fn new() -> Self {
        Veh {
            v_id: 0,
            /* 
            v_sk: PS_sk{
                X: G1::zero()
            },
            v_pk: PS_pk{
                g: G1::zero(),
                g_dash: G2::zero(),
                Y: Vec::new(),
                X_dash: G2::zero(),
                Y_dash: Vec::new(),
            },
            */
            sig_e: G1::zero(),
            cred_ps: (Fr::zero(), (G1::zero(), G1::zero()), (G1::zero(), Fr::zero()), G1::zero()),
            cred: (0, 0, (Fr::zero(), G1::zero(), G1::zero())),
            pke_ek: G2::zero(),
            pke_dk: Fr::zero(),
            ticket_q: VecDeque::new(),
            bl_size: 0,
            commit_pie: (G1::zero(), (Fr::zero(), Fr::zero(), Vec::new()), Fr::zero()),
            wt_map: HashMap::new(),
            vt: G1::zero(),
            q_id: Fr::zero()
        }

    }

    // Key generation function for EA
    pub fn Veh_key_gen(&mut self, rng: &mut XorShiftRng, id: u128, k: u64) {
        // Generate a random secret key
       // let (sk, pk) = PS::ps_keygen(rng, k);
        //self.v_sk = sk;
        //self.v_pk = pk;
        self.v_id = id;
    }
     
    pub fn init_ticket_q(&mut self, k: u64, ia: &mut IA::IA){
        for _ in 0..k{
            self.ticket_q.push_back(ia.def_t);
        }
    }

    pub fn register_user_s1(
        &mut self,
        k: u64,
        ia: &mut IA::IA,
        epoch: Fr,
        g: G1,
        vid: Fr
    )  {
        let q_star = gen_random_fr(&mut get_random_rng());
        let q_hat = self.ticket_q.pop_front().unwrap();
        self.ticket_q.push_back(q_star);
        let commit_p = GenCommitment(&ia.ps_pk, &mut self.ticket_q, k);
        let r = commit_p.2;
        let sigma_star_wt = ia.register_user_i(&commit_p, epoch, k, g, q_hat, vid);
        self.bl_size = ia.block_list.len();
        let (sigma_star, wt) = sigma_star_wt.unwrap();

        
        
        let a = fr_to_bytes(&q_hat);
        self.wt_map.insert(a, wt);
            
        self.vt = ia.vt;
        self.commit_pie = commit_p;
        let  (sigma_1, sigma_2, _) = sigma_star;
        let sigma_un = Unblind(&mut (sigma_1, sigma_2), r);
        let sigma_ver = verify(sigma_un, &mut self.ticket_q, epoch, &ia.ps_pk, k);
        let wt_ver = ver_nonmem(ia.vt, q_hat, wt, ia.a_pk, g);
        println!("sigma_ver: {}", sigma_ver);
        println!("wt_ver: {}", wt_ver);
        
        if(sigma_ver == false || wt_ver == false){
            println!("Not Verify at registration\n");
        }else{
            self.cred_ps  = Some((epoch, sigma_un, wt, ia.vt)).unwrap();
            println!("Size of bl: {}", self.bl_size);
        }
        
    }

    pub fn authenticate_user_s1(
        &mut self,
        k: u64,
        ia: &mut IA::IA,
        //commit_1: &(G1, (Fr, Fr, Vec<Fr>), Fr),
        e_j: Fr
    ) {
        let mut found = false;
    
        for ticket in &self.ticket_q {
            if ia.block_list.contains(ticket) {
                found = true;
                break;
            }
        }

        if found {
            println!("One of the ticket is blocklisted");
        } else {
            println!("none of the tickets are blocklisted");
        }
        

        let g = G1::one();
        let g2 = G2::one();
        let ( e_i, sigma, wt, vt) = self.cred_ps;
        
        let q_star = gen_random_fr(&mut get_random_rng());
        let q_hat = self.ticket_q.pop_front().unwrap();
        let a = fr_to_bytes(&q_hat);
        
        let q_k = *self.ticket_q.back().unwrap();
        self.q_id = q_k; 
        self.ticket_q.push_back(q_star);

        if self.bl_size < ia.block_list.len(){
            for j in self.bl_size..{
                let y = ia.block_list.get(j).unwrap();
                for i in 0..k-2 {
                    if let Some(value) = self.ticket_q.get(i.try_into().unwrap()) {
                        let a = fr_to_bytes(value);
                        let wt = self.wt_map.get(&a).unwrap();
                        let new_wt = nonmem_update(self.vt, *value, *y, *wt);
                        self.wt_map.insert(a, new_wt);
                    }
                }
            }
        }

        let mut zkp_non: Vec<(Fr, Fr, Fr, Fr, Fr, Fr, Fr, G2, G1, G1, G2, G1, G2, G2, Fq12)> = Vec::new();
        for i in 0..k-2{
            if let Some(value) = self.ticket_q.get(i.try_into().unwrap()) {
                let a = fr_to_bytes(value);
                let wt = self.wt_map.get(&a).unwrap();
                let zkp = zkp_non_mem(g, g2, *wt, vt, *value, ia.a_pk);
                zkp_non.push(zkp);
            }
        }

        let commit_2 = GenCommitment(&ia.ps_pk, &mut self.ticket_q, k);
        let commit_3 = commit_2.clone();
        let r_dash = gen_random_fr(&mut get_random_rng());
        let sigma_r1 = (mul_g1_fr(sigma.0, &r_dash), mul_g1_fr(sigma.1, &r_dash));
        let zkpok_q_sigma = zkp_sign_q(sigma_r1, &ia.ps_pk, self.commit_pie.0, commit_2.0, &mut self.ticket_q, self.commit_pie.2, commit_2.2, q_hat);
        let req = (q_k, e_i, sigma_r1, zkpok_q_sigma, commit_2, e_j);
        let sigma_star_wt = ia.authenticate_user_i(&req, e_j, k, g, zkp_non);
        
        let e_j_1 = add_fr_fr(e_j, &int_to_fr(&1));
        self.bl_size = ia.block_list.len();
        let (sigma_star, wt) = sigma_star_wt.unwrap();
        self.commit_pie = commit_3;
        let  (sigma_1, sigma_2, _) = sigma_star;
        let sigma_un = Unblind(&mut (sigma_1, sigma_2), self.commit_pie.2);
        let sigma_ver = verify(sigma_un, &mut self.ticket_q, e_j_1, &ia.ps_pk, k);
        let wt_ver = ver_nonmem(ia.vt, q_k, wt, ia.a_pk, g);
        println!("sigma_ver: {}", sigma_ver);
        println!("wt_ver: {}", wt_ver);
        
        if(sigma_ver == false || wt_ver == false){
            println!("Not Verify********\n");
        }else{
            self.cred_ps  = Some((e_j_1, sigma_un, wt, ia.vt)).unwrap();
            println!("Size of bl: {}", self.bl_size);
        }
        
    }



    /* 
    pub fn SIG_verify(&mut self, e_pk: &G2, sig: &G1) -> Option<CertV> {
        let verify = BLS::bls_verify_vid_vpk(e_pk, self.v_id, self.v_pk, sig);
        if verify {
            self.sig_e = *sig;
            println!("Verification Successful for vehicle {}\n", self.v_id);
            Some(CertV {
                sk: self.v_sk,
                pk: self.v_pk,
                sig_e: *sig,
            })
        } else {
            println!("Verification Failed for vehicle {}\n", self.v_id);
            None
        }
    }
    

    pub fn SIG_sig_epoch(&mut self, epoch: u128) -> G1 {
        let signature_epoch = BLS::bls_sign_epoch(&self.v_sk, epoch);
        if let sig = &signature_epoch {
            println!("Signing Successful for epcoch {}\n", epoch);
        } else {
            println!("Signing Failed for epoch {}\n", epoch);
        }
        signature_epoch
    }
    */

    pub fn get_cred(
        &mut self,
        sigma: &(Fr, G1, G1),
        IAPublicKey: &IAPublicKey,
        epoch: u128,
    ) -> Option<(u128, u128, (Fr, G1, G1))> {
        let result = DGSA::issue_v(&sigma, &self.v_id, &epoch, IAPublicKey);
        // println!("Verification result: {:?}", result);

        if result {
            let cred = Some((self.v_id.clone(), epoch.clone(), *sigma));
            self.cred = cred.unwrap();
            cred
        } else {
            println!("Verification Failed\n");
            None
        }
    }

    pub fn Vehicle_PKE_Key_gen(&mut self, rng: &mut XorShiftRng) -> (G2, Fr) {
        let (pke_pk, pke_sk) = PKE::pke_key_gen(rng);
        self.pke_ek = pke_pk;
        self.pke_dk = pke_sk;
        (pke_pk, pke_sk)
    }

    fn create_m_from_pk(&mut self) -> (u128, (Fr, G1, G1), u128, u128) {
        let (cred_vid, cred_epoch, sigma) = self.cred;
        let pke_pk_u128_vec = util::g2_to_vec_u128(self.pke_ek);
        let pke_pk_u128 = util::combine_vec_u128(pke_pk_u128_vec);

        let m = cred_vid + cred_epoch + pke_pk_u128;
        (m, sigma, cred_epoch, cred_vid)
    }

    fn create_m_from_encrypted_zk(
        &mut self,
        zpk_encrypt_ct: u128,
    ) -> (u128, (Fr, G1, G1), u128, u128) {
        let (cred_wid, cred_wepoch, sigma_w) = self.cred;
        let m = cred_wid + cred_wepoch + zpk_encrypt_ct;
        (m, sigma_w, cred_wepoch, cred_wid)
    }

    pub fn generate_token_m(
        &mut self,
        rng: &mut XorShiftRng,
        IAPublicKey: &IAPublicKey,
        f: bool,
        zpk_encrypt_ct: u128,
    ) -> ((G1, G1, (Fr, (Fr, Fr))), u128) {
        let m;
        let sigma;
        let cred_epoch;
        let cred_id;
        if f {
            (m, sigma, cred_epoch, cred_id) = self.create_m_from_pk();
        } else {
            (m, sigma, cred_epoch, cred_id) = self.create_m_from_encrypted_zk(zpk_encrypt_ct);
        }

        let token = DGSA::auth(rng, &m, &sigma, &cred_id, &cred_epoch, &IAPublicKey);

        (token, m)
    }

    pub fn verify_token(
        token: (G1, G1, (Fr, (Fr, Fr))),
        IAPublicKey: &IAPublicKey,
        message: u128,
        epoch: u128,
    ) -> bool {
        let (sigma_v1_dash, sigma_v2_dash, pie_v) = token;

        let is_valid = DGSA::Vf(
            &sigma_v1_dash,
            &sigma_v2_dash,
            &pie_v,
            *IAPublicKey,
            message,
            &epoch,
        );

        is_valid
    }

    pub fn Zone_sk_PKE_encryption(rng: &mut XorShiftRng, pke_ek: G2, zone_pre_sk: &G2) -> (G2, G2) {
        let (zpk_encrypted_c1, zpk_encrypted_c2) = PKE::pke_encrypt(rng, pke_ek, *zone_pre_sk);
        (zpk_encrypted_c1, zpk_encrypted_c2)
    }

    pub fn Zone_sk_PKE_decryption(pke_dk: Fr, zpk_encrypted_c1: G2, zpk_encrypted_c2: G2) -> G2 {
        PKE::pke_decrypt(&pke_dk, (zpk_encrypted_c1, zpk_encrypted_c2))
    }
    pub fn SE_Key_gen(
        rng: &mut XorShiftRng,
    ) -> GenericArray<u8, <Aes128GcmSiv as NewAead>::KeySize> {
        let key: [u8; 16] = rng.gen();
        let kp = GenericArray::clone_from_slice(&key);
        kp
    }
    pub fn SE_encryption(
        payload: &str,
        kp: GenericArray<u8, <Aes128GcmSiv as NewAead>::KeySize>,
    ) -> (Vec<u8>, GenericArray<u8, U12>) {
        let (cipher_payload_v, nonce_payload_v) = SE::encrypt(kp, payload);
        (cipher_payload_v, nonce_payload_v)
    }

    pub fn SE_decryption(
        kp: GenericArray<u8, <Aes128GcmSiv as NewAead>::KeySize>,
        nonce: &GenericArray<u8, <Aes128GcmSiv as Aead>::NonceSize>,
        ciphertext: &[u8],
    ) -> String {
        let payload = SE::decrypt(kp, &nonce, &ciphertext);
        payload
    }

    pub fn DAE_encryption(
        Zpk: GenericArray<u8, <Aes128GcmSiv as NewAead>::KeySize>,
        kp: GenericArray<u8, <Aes128GcmSiv as NewAead>::KeySize>,
    ) -> (Vec<u8>, GenericArray<u8, U12>) {
        DAE::encrypt(Zpk, kp)
    }

    pub fn DAE_decryption(
        Zpk: GenericArray<u8, <Aes128GcmSiv as NewAead>::KeySize>,
        cipher_kp: (GenericArray<u8, generic_array::typenum::U12>, Vec<u8>),
    ) -> GenericArray<u8, <Aes128GcmSiv as NewAead>::KeySize> {
        let decrypted_kp = DAE::decrypt(Zpk, cipher_kp);
        decrypted_kp
    }
}
