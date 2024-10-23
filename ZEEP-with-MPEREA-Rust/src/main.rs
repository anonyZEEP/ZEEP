use pairing::CurveProjective;
use rand::{SeedableRng, XorShiftRng};
use util::{  combine_vec_u128,  fr_to_int, g2_to_vec_u128,  int_to_fr};
use PS::ps_keygen;
use pairing::bls12_381::{G1, G2};

mod PS;
mod util;

mod PKE;
mod Accumulator;
mod MPEREA;
mod DGSA;
mod IA;
mod vehicle;
mod DAE;
mod SE;
mod Zone;


extern crate aes_gcm_siv;
extern crate pairing;
extern crate rand;
extern crate sha2;
extern crate rand_xorshift;


fn process_encryption(zpk_encryption_c1: G2, zpk_encryption_c2: G2) -> u128 {
    let zpk_encrypt_1_vec_u128 = g2_to_vec_u128(zpk_encryption_c1);
    let zpk_encrypt_2_vec_u128 = g2_to_vec_u128(zpk_encryption_c2);

    let mut concatenated_vec = zpk_encrypt_1_vec_u128.clone();
    concatenated_vec.extend(zpk_encrypt_2_vec_u128);

    // Combine the concatenated vector into a single u128
    let zpk_encrypt_u128 = combine_vec_u128(concatenated_vec);

    zpk_encrypt_u128
}
fn uptil_DGSA(
    ia: &mut IA::IA,
    epoch: u128,
    no_of_veh: usize,
    mut rng: &mut XorShiftRng,
    k: u64
) -> Vec<vehicle::Veh> {
    let mut vehicles = Vec::with_capacity(no_of_veh);
    // Create a new vehicle instance
    let id = 10000;

    for i in 0..no_of_veh {
        let mut veh = vehicle::Veh::new();

        let vid = (id + (i * 10000)).try_into().unwrap();
        veh.Veh_key_gen(&mut rng, vid, k.try_into().unwrap());
        let g = G1::one();
        let e = int_to_fr(&epoch);
        let v_id = int_to_fr(&vid);
        veh.init_ticket_q(k, ia);
        
        veh.register_user_s1(k, ia, e, g, v_id);
        
        veh.authenticate_user_s1(k, ia, e);
        
        let vid_fr = veh.q_id;
        let q_id = fr_to_int(&vid_fr);
        
        let sigma_v1 = ia.compute_sigma(&mut rng, vid, epoch);

        let cred_v1 = veh.get_cred(&sigma_v1.unwrap(), &ia.IAPublicKey, epoch);

        // println!("cred_v1 {:?}\n", cred_v1);
        vehicles.push(veh);
    }

    vehicles
}

fn after_DGSA(
    veh1: &mut vehicle::Veh,
    veh2: &mut vehicle::Veh,
    ia: &mut IA::IA,
    epoch: u128,
    mut rng: &mut XorShiftRng,
) {

    
    // //ENTER
    // //1. 𝒱 running Enter.V(cred 𝒱 , 𝐿𝐾 , pk ℐ , 𝑧, 𝑡, requester )
    let (v_pke_ek, v_pke_dk) = veh1.Vehicle_PKE_Key_gen(&mut rng);


    let (token_v, m) = veh1.generate_token_m(&mut rng, &ia.IAPublicKey, true, 0);


    println!("Token: is generated for vehicle v\n",);

    // //FOR vehicle v2

    // //2. 𝒲𝑖 running Enter.W(cred 𝒲𝑖 , 𝐿𝐾𝑖 , pk ℐ , 𝑧, 𝑡, responder 𝑖 ) upon receiving (𝑧,𝑡, ek , tok 𝒱 ) from a vehicle 𝒱:
    let is_valid_token_v = vehicle::Veh::verify_token(token_v, &ia.IAPublicKey, m, epoch);

    // println!("For vehicke v token is valid: {}\n", is_valid_token_v);

    let mut Zone1 = Zone::Zone::new();
    let zid1 = 1234;
    let zone_pre_sk = Zone1.Zone_key_gen(&mut rng, zid1);

    let Zpk_sk_v2 = Zone1.generate_zone_sk_key(zone_pre_sk);
    // println!("zpk_sk_v2 {:?}\n", Zpk_sk_v2);



    let (zpk_encrypted_c1, zpk_encrypted_c2) =
        vehicle::Veh::Zone_sk_PKE_encryption(&mut rng, v_pke_ek, &zone_pre_sk);

    let zpk_encrypt_ct = process_encryption(zpk_encrypted_c1, zpk_encrypted_c2);

    let (token_v2, m1) = veh2.generate_token_m(&mut rng, &ia.IAPublicKey, false, zpk_encrypt_ct);

    // // 3.Vehicle 𝒱 upon receiving (𝑧, 𝑡, ct, tok 𝒲 ) from a vehicle 𝒲𝑖 :

    let is_valid_token_v2 = vehicle::Veh::verify_token(token_v2, &ia.IAPublicKey, m1, epoch);

    // println!("For vehicke v2 token is valid: {}\n", is_valid_token_v2);

    let zone_pre_sk_v =
        vehicle::Veh::Zone_sk_PKE_decryption(v_pke_dk, zpk_encrypted_c1, zpk_encrypted_c2);
    // println!("zone_pre_sk: {}\n", { zone_pre_sk });
    // println!("zone_pre_sk_w {}\n", { zone_pre_sk_v });


    let Zpk_sk_v = Zone1.generate_zone_sk_key(zone_pre_sk_v);
    // println!("zpk_sk_v {:?}\n", Zpk_sk_v);


    // ////Sending and Receiving Payloads.

    // // Send(𝐿𝐾 , P , 𝑌 ⊆ 𝑍, 𝑡) :
    let payload_v = "123456789";
    let kp = vehicle::Veh::SE_Key_gen(&mut rng);

    let (cipher_payload_v, nonce_payload_v) = vehicle::Veh::SE_encryption(payload_v, kp);

    let (cipher_kp_v, iv_kp_v) = vehicle::Veh::DAE_encryption(Zpk_sk_v, kp);


    let message_v1_to_v2 = (cipher_payload_v, nonce_payload_v, cipher_kp_v, iv_kp_v);


    let (cipher_payload_v2, nonce_payload_v2, cipher_kp_v2, iv_kp_v2) = message_v1_to_v2;


    let decrypted_kp = vehicle::Veh::DAE_decryption(Zpk_sk_v2, (iv_kp_v2, cipher_kp_v2));

    // // println!("decrypted_kp {:?}\n", decrypted_kp);
    let payload_w =
        vehicle::Veh::SE_decryption(decrypted_kp, &nonce_payload_v2, &cipher_payload_v2);

    // println!("payload_w: {}", payload_w);
}
fn main() {
    let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    let k = 5;
    let kk = ps_keygen(&mut rng, 5);
    let mut ia = IA::IA::new();
    ia.IA_key_gen(&mut rng, k.try_into().unwrap());
    ia.fill_bl(10);
    let epoch = 100;
    let no_of_vehicles = 2;
    let mut vehicles = uptil_DGSA(&mut ia, epoch, no_of_vehicles, &mut rng, k);

    if vehicles.len() >= 2 {
        let (first, rest) = vehicles.split_at_mut(1);
        let veh1 = &mut first[0];
        let veh2 = &mut rest[0];
        after_DGSA(veh1, veh2, &mut ia, epoch, &mut rng);
    } else {
        println!("Not enough vehicles to process.");
    }
}