extern crate aes_gcm_siv;
extern crate pairing;
extern crate rand;
extern crate sha2;

use crate::BLS;
use pairing::{bls12_381::*, CurveProjective, Field};
use rand::{Rng, SeedableRng, XorShiftRng};
use std::collections::{HashMap, HashSet};
use std::mem;
use std::time::{Duration, Instant};

pub struct EA {
    e_sk: Fr,
    pub e_pk: G2,
    e_set: HashSet<u128>,
}

impl EA {
    // Constructor for EA that initializes sk and pk to default values
    pub fn new() -> Self {
        EA {
            e_sk: Fr::zero(), // Initialize sk to zero (or any default value)
            e_pk: G2::zero(), // Initialize pk to zero (or any default value)
            e_set: HashSet::new(),
        }
    }

    // Key generation function for EA
    pub fn EA_key_gen(&mut self, rng: &mut XorShiftRng) {
        // Generate a random secret key
        let (pk, sk) = BLS::bls_key_gen(rng);
        let mut set: HashSet<u128> = HashSet::new();
        self.e_sk = sk;
        self.e_pk = pk;
        self.e_set = set;
    }

    pub fn SIG_sig(&mut self, vid1: u128, v_pk: &G2) -> Option<G1> {
        let signature_e = BLS::bls_sign_vid_vpk(&self.e_sk, vid1, &v_pk, &mut self.e_set);
        if let Some(sig) = &signature_e {
            println!("Signing Successful for vehicle {}\n", vid1);
        } else {
            println!("Signing Failed for vehicle {}\n", vid1);
        }
        signature_e
    }
}
