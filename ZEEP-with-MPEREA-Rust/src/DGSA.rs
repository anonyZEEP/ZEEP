extern crate bit_vec;
extern crate blake2;
extern crate byteorder;
extern crate pairing;
extern crate rand;

use pairing::bls12_381::*;
use pairing::*;
use rand::XorShiftRng;
use std::collections::HashMap;

use crate::util::{self, *};
//use crate::IA;

pub fn keygen(rng: &mut XorShiftRng) -> (Fr, Fr, Fr, Fr, G2, G2, G2, G2, G2) {
    let g2 = G2::one();

    // sk
    let x2 = gen_random_fr(rng);
    let y_id = gen_random_fr(rng);
    let y_epoch = gen_random_fr(rng);
    let y_k1 = gen_random_fr(rng);

    // pk
    let X2 = mul_g2_fr(g2, &x2);
    let Y_id = mul_g2_fr(g2, &y_id);
    let Y_epoch = mul_g2_fr(g2, &y_epoch);
    let Y_K1 = mul_g2_fr(g2, &y_k1);

    // SET
    // println!("{}", { "\nKEY GENERATION......\n" });
    // print_g2("g2", &g2);
    // print_fr("x2", &x2);
    // print_fr("y_id", &y_id);
    // print_fr("y_epoch", &y_epoch);
    // print_fr("y_k1", &y_k1);
    // print_g2("X2", &X2);
    // print_g2("Y_id", &Y_id);
    // print_g2("Y_epoch", &Y_epoch);
    // print_g2("Y_k1", &Y_K1);
    (x2, y_id, y_epoch, y_k1, X2, Y_id, Y_epoch, Y_K1, g2)
}

pub fn issue_i<'a>(
    rng: &mut XorShiftRng,
    IASecretKey: &IASecretKey,
    id: &u128,
    epoch: &u128,
    set: &mut HashMap<(u128, u128), Fr>,
) -> Option<((Fr, G1, G1), HashMap<(u128, u128), Fr>)> {
    let a_dash = gen_random_fr(rng);

    if set.contains_key(&(*id, *epoch)) {
        println!("The key (id, epoch) is present in the map.");
        return None; // Exit the function early if the key is present
    } else {
        // println!("The key (id, epoch) is not present in the map.");
        set.insert((*id, *epoch), a_dash.clone());
    }

    let h = G1::one();

    // converting id and epoch to field element
    let id_fr = int_to_fr(id);
    let epoch_fr = int_to_fr(epoch);

    let mut pw = IASecretKey.sk_x2.clone();
    pw = add_fr_fr(pw, &mul_fr_fr(id_fr, &IASecretKey.sk_id));
    pw = add_fr_fr(pw, &mul_fr_fr(epoch_fr, &IASecretKey.sk_epoch));
    pw = add_fr_fr(pw, &mul_fr_fr(a_dash, &IASecretKey.sk_k1));

    let sigma_2 = mul_g1_fr(h, &pw);

    let sigma = (a_dash, h, sigma_2);

    // println!("{}", { "\nISSUE_I......\n" });
    //  print_fr("a_dash", &a_dash);
    //  print_g1("h", &h);
    //  print_fr("pw", &pw);
    //  print_g1("sigma_2", &sigma_2);

    Some((sigma, set.clone()))
}
pub fn issue_v(
    sigma: &(Fr, G1, G1),
    id: &u128,
    epoch: &u128,
    IAPublicKey: &IAPublicKey,
) -> bool {
    // converting id and epoch to field element
    let (a_dash, h, sigma_2) = sigma;
    let id_fr = int_to_fr(id);
    let epoch_fr = int_to_fr(epoch);
    

    let mut XYY = IAPublicKey.pk_X2.clone();

    XYY = add_g2_g2(XYY, mul_g2_fr(IAPublicKey.pk_id, &id_fr));
    XYY = add_g2_g2(XYY, mul_g2_fr(IAPublicKey.pk_epoch, &epoch_fr));
    XYY = add_g2_g2(XYY, mul_g2_fr(IAPublicKey.pk_K1, a_dash));

    let pair1 = do_pairing(&h.into_affine(), &XYY.into_affine());
    let pair2 = do_pairing(&sigma_2.into_affine(), &IAPublicKey.g2.into_affine());

    // println!("{}", { "\nISSUE_U......\n" });
    //  print_g2("XYY", &XYY);
    //  print_gt("pair1", &pair1);
    //  print_gt("pair2", &pair2);
    pair1 == pair2
}

pub fn auth(
    rng: &mut XorShiftRng,
    m: &u128,
    sigma: &(Fr, G1, G1),
    id: &u128,
    epoch: &u128,
    IAPublicKey: &IAPublicKey,
) -> (G1, G1, (Fr, (Fr, Fr))) {
    let (a_dash, sigma_1, sigma_2) = sigma;
    let id_fr = int_to_fr(id);
    let epoch_fr = int_to_fr(epoch);

    let r = gen_random_fr(rng);

    let sigma_1_dash = mul_g1_fr(*sigma_1, &r);
    let sigma_2_dash = mul_g1_fr(*sigma_2, &r);
    // println!("sigma_1_dash {:?}\n", sigma_1_dash);
    // println!("sigma_2_dash {:?}\n", sigma_2_dash);
    let s_id = gen_random_fr(rng);
    let s_a_dash = gen_random_fr(rng);

    let p1 = do_pairing(
        &mul_g1_fr(sigma_1_dash, &s_id).into_affine(),
        &IAPublicKey.pk_id.into_affine(),
    );
    let p2 = do_pairing(
        &mul_g1_fr(sigma_1_dash, &s_a_dash).into_affine(),
        &IAPublicKey.pk_K1.into_affine(),
    );

    let u = mul_fq12_fq12(p1, p2);
    // println!("u: {:?}\n", u);
    // println!("m: {:?}", m);
    let c = combine_to_fr(
        &u,
        &epoch_fr,
        &m,
        &sigma_1_dash,
        &sigma_2_dash,
        &IAPublicKey.pk_X2,
        &IAPublicKey.pk_epoch,
        &IAPublicKey.pk_id,
        &IAPublicKey.pk_K1,
    );

    // let test0 = util::minus_fr_fr(int_to_fr(&1), &int_to_fr(&1));
    // println!("test0: {:?}\n", test0);

    let vid = minus_fr_fr(s_id, &mul_fr_fr(c, &id_fr));
    let va_dash = minus_fr_fr(s_a_dash, &mul_fr_fr(c, &a_dash));
    // println!("vid {:?}\n", vid);
    // println!("va_dash {:?}\n", va_dash);

    ////////////////////////////////////////////////////////////////////////

    /////////////////////////////////////////////////////////////
    let v = (vid, va_dash);

    let pie = (c, v);

    // println!("pie {:?}\n", pie);
    let token = (sigma_1_dash, sigma_2_dash, pie);

    // Output the results
    // println!("{}", { "\nAUTH......\n" });
    token
}

pub fn Vf(
    sigma_1_dash: &G1,
    sigma_2_dash: &G1,
    pie: &(Fr, (Fr, Fr)),
    IAPublicKey: IAPublicKey,
    m: u128,
    epoch: &u128,
) -> bool {
    // println!("pie {:?}\n", pie);
    // println!("sigma_1_dash {:?}\n", sigma_1_dash);
    // println!("sigma_2_dash {:?}\n", sigma_2_dash);
    let (c, v) = pie; // Destructure the tuple into its components

    let (vid, va_dash) = v;
    // println!("vid {:?}\n", vid);
    // println!("va_dash {:?}\n", va_dash);
    let epoch_fr = int_to_fr(epoch);

    let p1 = do_pairing(
        &mul_g1_fr(*sigma_1_dash, &vid).into_affine(),
        &IAPublicKey.pk_id.into_affine(),
    );

    let p2 = do_pairing(
        &mul_g1_fr(*sigma_1_dash, &va_dash).into_affine(),
        &IAPublicKey.pk_K1.into_affine(),
    );

    let p3 = do_pairing(
        &mul_g1_fr(*sigma_2_dash, &c).into_affine(),
        &IAPublicKey.g2.into_affine(),
    );

    // let inv: u128 = -1;
    let mut XY_inverse = mul_g2_fr(IAPublicKey.pk_X2, &int_to_fr_negate(&1));

    let mut epoch_neg = epoch_fr.clone();
    epoch_neg.negate();
    XY_inverse = add_g2_g2(XY_inverse, mul_g2_fr(IAPublicKey.pk_epoch, &epoch_neg));

    let p4 = do_pairing(
        &mul_g1_fr(*sigma_1_dash, &c).into_affine(),
        &XY_inverse.into_affine(),
    );

    let u1 = mul_fq12_fq12(p1, mul_fq12_fq12(p2, mul_fq12_fq12(p3, p4)));
    // println!("{:?}", u1);
    // println!("u1: {:?}\n", u1);
    // println!("m: {:?}", m);
    let c1 = combine_to_fr(
        &u1,
        &epoch_fr,
        &m,
        &sigma_1_dash,
        &sigma_2_dash,
        &IAPublicKey.pk_X2,
        &IAPublicKey.pk_epoch,
        &IAPublicKey.pk_id,
        &IAPublicKey.pk_K1,
    );

    // println!("{}", { "\nVF......\n" });

    // print_fr("c", c);
    // print_fr("c1", &c1);
    //  print_fr("c2", &c2);

    c == &c1
}
