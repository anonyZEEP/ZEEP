extern crate aes_gcm_siv;
extern crate pairing;
extern crate rand;
extern crate sha2;

use crate::{
    util::{self, gen_random_fr},
    DAE,
};
use aes_gcm_siv::{aead::NewAead, Aes128GcmSiv};
use pairing::{bls12_381::*, CurveProjective};
use rand::XorShiftRng;
use sha2::digest::generic_array::GenericArray;

pub struct Zone {
    pub zone_id: u128,
    pub zone_pre_sk: G2,
    pub zone_sk: GenericArray<u8, <Aes128GcmSiv as NewAead>::KeySize>,
}

impl Zone {
    // Constructor for EA that initializes sk and pk to default values
    pub fn new() -> Self {
        Zone {
            zone_id: 0,
            zone_pre_sk: G2::zero(), // Initialize sk to zero (or any default value)
            zone_sk: GenericArray::default(), // Initialize pk to zero (or any default value)
        }
    }

    // Key generation function for EA
    pub fn Zone_key_gen(&mut self, mut rng: &mut XorShiftRng, zid: u128) -> G2 {
        // Generate a random secret key
        let sk_fr = gen_random_fr(&mut rng);
        let g = G2::one();
        let zone_pre_sk = util::mul_g2_fr(g, &sk_fr);
        self.zone_id = zid;
        self.zone_pre_sk = zone_pre_sk;
        zone_pre_sk
    }

    pub fn generate_zone_sk_key(
        &mut self,
        zone_pre_sk: G2,
    ) -> (GenericArray<u8, <Aes128GcmSiv as NewAead>::KeySize>) {
        let zone_sk = DAE::generate_key(zone_pre_sk);
        self.zone_sk = zone_sk;
        zone_sk
    }
}
