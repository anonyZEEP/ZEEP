extern crate aes_gcm_siv;
extern crate pairing;
extern crate rand;
extern crate sha2;

use crate::{
    util::{
        combine_vec_u128, g2_to_vec_u128, gen_random_fr, mul_g1_fr, CertV, IAPublicKey, IASecretKey,
    },
    BLS, DGSA,
};
use pairing::{bls12_381::*, CurveProjective, Field};
use rand::{Rng, SeedableRng, XorShiftRng};
use std::{
    collections::{HashMap, HashSet},
    option,
};

pub struct IA {
    IASecretKey: IASecretKey,
    pub IAPublicKey: IAPublicKey,
    pub set_i: HashMap<(u128, u128), Fr>,
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
            set_i: HashMap::new(),
        }
    }

    // Key generation function for EA
    pub fn IA_key_gen(&mut self, mut rng: &mut XorShiftRng) {
        // Generate a random secret key
        let attribute = 1;
        let (sk_x2, sk_id, sk_epoch, sk_k1, pk_X2, pk_id, pk_epoch, pk_K1, g2) =
            DGSA::keygen(&mut rng, attribute);
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
    }

    pub fn verify_authorization(
        e_pk: &G2,
        vid: u128,
        v_pk: &G2,
        epoch: u128,
        sig_e: &G1,
        sig_v: &G1,
    ) -> bool {
        let check_vid_vpk = BLS::bls_verify_vid_vpk(e_pk, vid, *v_pk, sig_e);
        let check_e = BLS::bls_verify_epoch(v_pk, epoch, sig_v);

        check_e && check_vid_vpk
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
