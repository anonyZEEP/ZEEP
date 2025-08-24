use sha2::{Digest, Sha256};
use pairing::{
    bls12_381::{Fr, FrRepr, G1, G1Affine},
    CurveAffine, CurveProjective, EncodedPoint, Field, PrimeField,
};
use std::collections::{HashMap, HashSet};
use std::time::Instant;

// ---------- small utils ----------

fn sha256_bytes(tag: &str, data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(tag.as_bytes());
    h.update(data);
    let out = h.finalize();
    let mut b = [0u8; 32];
    b.copy_from_slice(&out);
    b
}

// Convert 32 bytes (big-endian) -> Fr (via Fr::from_repr)
fn be32_to_fr(bytes: [u8; 32]) -> Option<Fr> {

    let mut limbs = [0u64; 4];
    limbs[3] = u64::from_be_bytes(bytes[0..8].try_into().unwrap());
    limbs[2] = u64::from_be_bytes(bytes[8..16].try_into().unwrap());
    limbs[1] = u64::from_be_bytes(bytes[16..24].try_into().unwrap());
    limbs[0] = u64::from_be_bytes(bytes[24..32].try_into().unwrap());
    Fr::from_repr(FrRepr(limbs)).ok()
}

// Hash-to-field: SHA256(tag || ctr || data)
fn hash_to_fr(tag: &str, data: &[u8]) -> Fr {
    let mut ctr: u32 = 0;

    loop {
        let mut h = Sha256::new();
        h.update(tag.as_bytes());
        h.update(&ctr.to_be_bytes());
        h.update(data);
        let out = h.finalize();
        let mut b = [0u8; 32];
        b.copy_from_slice(&out);
        if let Some(fr) = be32_to_fr(b) {
            return fr;
        }
        ctr = ctr.wrapping_add(1);
    }
}

fn fr_to_hex(x: &Fr) -> String {

    let repr: FrRepr = x.into_repr();
    let limbs = repr.as_ref(); 
    let mut s = String::new();

    for limb in limbs.iter().rev() {
        s.push_str(&format!("{:016x}", limb));
    }

    let s = s.trim_start_matches('0');
    if s.is_empty() { "0".to_string() } else { s.to_string() }
}

fn g1_mul_fr(base: &G1, k: &Fr) -> G1 {
    let mut p = *base;
    p.mul_assign(*k);
    p
}

fn g1_from_compressed(bytes: &[u8; 48]) -> G1 {
    let mut c = <G1Affine as CurveAffine>::Compressed::empty();
    c.as_mut().copy_from_slice(bytes);
    let aff = c.into_affine().expect("invalid compressed G1 point");
    aff.into_projective()
}

fn g1_to_compressed(p: &G1) -> [u8; 48] {
    let aff: G1Affine = (*p).into_affine();
    let c = aff.into_compressed();
    let mut out = [0u8; 48];
    out.copy_from_slice(c.as_ref());
    out
}

// hex encoder
mod hexs {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    pub fn encode<T: AsRef<[u8]>>(data: T) -> String {
        let b = data.as_ref();
        let mut out = Vec::with_capacity(b.len() * 2);

        for &x in b {
            out.push(HEX[(x >> 4) as usize]);
            out.push(HEX[(x & 0x0f) as usize]);
        }

        unsafe { String::from_utf8_unchecked(out) }
    }
}

// ---------- KDF / HMAC / stream ----------

fn hkdf_one(label: &str, ikm: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(label.as_bytes());
    h.update(ikm);
    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut key_block = [0u8; 64];

    if key.len() > 64 {
        let d = Sha256::digest(key);
        key_block[..32].copy_from_slice(&d);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];

    for i in 0..64 { ipad[i] ^= key_block[i]; opad[i] ^= key_block[i]; }

    let mut ih = Sha256::new();
    ih.update(&ipad);
    ih.update(msg);
    let inner = ih.finalize();

    let mut oh = Sha256::new();
    oh.update(&opad);
    oh.update(&inner);
    let out = oh.finalize();
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&out);
    tag
}

fn stream_xor_encrypt(key: &[u8; 32], nonce: &[u8]) -> impl Fn(&[u8]) -> Vec<u8> {
    let mut seed = Vec::with_capacity(key.len() + nonce.len());
    seed.extend_from_slice(key);
    seed.extend_from_slice(nonce);
    move |pt: &[u8]| {
        let mut out = Vec::with_capacity(pt.len());
        let mut counter: u64 = 0;
        let mut off = 0;

        while off < pt.len() {
            let mut h = Sha256::new();
            h.update(&seed);
            h.update(&counter.to_be_bytes());
            let block = h.finalize();
            let take = core::cmp::min(32, pt.len() - off);
            for i in 0..take { out.push(pt[off + i] ^ block[i]); }
            off += take;
            counter += 1;
        }

        out
    }
}

// ---------- ECQV (Algorithm 1) core ----------

pub struct TAParams {
    pub d_ta: Fr,
    pub q_ta: G1,
    pub p_gen_compressed: [u8; 48],
    pub q_ta_compressed: [u8; 48],
}

pub fn ta_setup(seed: &[u8]) -> TAParams {
    let p = G1::one();
    let d_ta = hash_to_fr("TA-d", seed);
    let q_ta = g1_mul_fr(&p, &d_ta);
    TAParams {
        p_gen_compressed: g1_to_compressed(&p),
        q_ta_compressed: g1_to_compressed(&q_ta),
        d_ta,
        q_ta,
    }
}

#[derive(Clone)]
pub struct EcqvRequest {
    pub id: String,
    pub r_compressed: [u8; 48],
    pub k: Fr,
}

#[derive(Clone)]
pub struct EcqvResponse {
    pub r_recon: Fr,
    pub im_cert: String,
    pub p_v_compressed: [u8; 48],
}

pub fn ecqv_make_request(id: &str) -> EcqvRequest {
    let p = G1::one();
    let k = hash_to_fr("k-req", id.as_bytes()); 
    let r_point = g1_mul_fr(&p, &k);
    EcqvRequest { id: id.to_string(), r_compressed: g1_to_compressed(&r_point), k }
}

pub fn ecqv_ta_issue(params: &TAParams, req: &EcqvRequest) -> EcqvResponse {

    let p = G1::one();
    let k_ta = hash_to_fr("k-ta", &req.r_compressed);
    let r_v = g1_from_compressed(&req.r_compressed);
    let kta_p = g1_mul_fr(&p, &k_ta);
    let mut p_v = r_v;

    p_v.add_assign(&kta_p);
    let p_v_bytes = g1_to_compressed(&p_v);
    // imCert encode: hex(P_v || id)
    let mut blob = Vec::with_capacity(48 + req.id.as_bytes().len());
    blob.extend_from_slice(&p_v_bytes);
    blob.extend_from_slice(req.id.as_bytes());
    let im_cert = hexs::encode(blob);
    let e = hash_to_fr("e", im_cert.as_bytes());
    let mut r_recon = e;
    r_recon.mul_assign(&k_ta);
    r_recon.add_assign(&params.d_ta);
    EcqvResponse { r_recon, im_cert, p_v_compressed: p_v_bytes }
}

pub fn ecqv_compute_public(params: &TAParams, resp: &EcqvResponse) -> G1 {
    let e = hash_to_fr("e", resp.im_cert.as_bytes());
    let p_v = g1_from_compressed(&resp.p_v_compressed);
    let e_pv = g1_mul_fr(&p_v, &e);
    let mut q_v = e_pv;
    q_v.add_assign(&params.q_ta);
    q_v
}

pub fn ecqv_compute_private(req: &EcqvRequest, resp: &EcqvResponse) -> Fr {
    let e = hash_to_fr("e", resp.im_cert.as_bytes());
    let mut d_v = e;
    d_v.mul_assign(&req.k);
    d_v.add_assign(&resp.r_recon);
    d_v
}

// ---------- Registry for TA (stores imCert / ECQV response) ----------

#[derive(Clone)]
pub struct Registry {
    // id -> EcqvResponse (which contains imCert and P_v)
    pub entries: HashMap<String, EcqvResponse>,
    pub revoked: HashSet<String>,
}

impl Registry {
    pub fn new() -> Self {
        Registry { entries: HashMap::new(), revoked: HashSet::new() }
    }
    pub fn insert(&mut self, id: &str, resp: EcqvResponse) {
        self.entries.insert(id.to_string(), resp);
    }
    pub fn mark_revoked(&mut self, id: &str) {
        self.revoked.insert(id.to_string());
    }
    pub fn contains(&self, id: &str) -> bool {
        self.entries.contains_key(id)
    }
    pub fn get(&self, id: &str) -> Option<&EcqvResponse> {
        self.entries.get(id)
    }
}

// ---------- RSU & Vehicle registration ----------

pub fn rsu_registration(params: &TAParams, id: &str, registry: &mut Registry) -> (G1, Fr) {
    let req = ecqv_make_request(id);
    let resp = ecqv_ta_issue(params, &req);
    let q = ecqv_compute_public(params, &resp);
    let d = ecqv_compute_private(&req, &resp);
    // store TA-side record for later identity tracking
    registry.insert(id, resp.clone());
    (q, d)
}

pub fn vehicle_registration(params: &TAParams, id: &str, registry: &mut Registry) -> (G1, Fr) {
    let req = ecqv_make_request(id);
    let resp = ecqv_ta_issue(params, &req);
    let q = ecqv_compute_public(params, &resp);
    let d = ecqv_compute_private(&req, &resp);
    // store in registry (TA database)
    registry.insert(id, resp.clone());
    (q, d)
}

// ---------- Zone / VBS / V2V ----------

#[derive(Clone)]
pub struct ZoneKeys {
    pub zone: String,
    pub d_master: Fr,
    pub q_master: G1,
    pub d_bcast: Fr,
    pub q_bcast: G1,
}

pub fn ta_issue_zone_keys(zone: &str) -> ZoneKeys {
    let p = G1::one();

    let d_master = hash_to_fr("master", zone.as_bytes());
    let d_bcast = hash_to_fr("bcast", zone.as_bytes());
    let q_master = g1_mul_fr(&p, &d_master);
    let q_bcast = g1_mul_fr(&p, &d_bcast);

    ZoneKeys { zone: zone.to_string(), d_master, q_master, d_bcast, q_bcast }
}

#[derive(Clone)]
pub struct TAtoRSUToken {
    pub zone: String,
    pub q_master_compressed: [u8; 48],
    pub valid_secs: u32,
    pub ref_no: Fr,
}

pub fn ta_daily_handshake(zone: &ZoneKeys, rsu_id: &str) -> TAtoRSUToken {
    let q_m_aff: G1Affine = zone.q_master.into_affine();
    let mut q_m_bytes = [0u8; 48];
    q_m_bytes.copy_from_slice(q_m_aff.into_compressed().as_ref());
    let ref_no = hash_to_fr("zone-ref", format!("{}|{}", zone.zone, rsu_id).as_bytes());

    TAtoRSUToken { zone: zone.zone.clone(), q_master_compressed: q_m_bytes, valid_secs: 24*60*60, ref_no }
}

// RSU->Vehicle handshake: RSU picks a, sends alpha=aP, beta=aQv, mac over alpha
#[derive(Clone)]
pub struct RSUBroadcastMsg {
    pub alpha_compressed: [u8;48],
    pub beta_compressed: [u8;48],
    pub mac: [u8;32],
}

pub fn rsu_to_vehicle_handshake(vehicle_pub: &G1, rsu_seed: &[u8]) -> (RSUBroadcastMsg, [u8;32], [u8;32]) {
    let a = hash_to_fr("rsu-ephemeral", rsu_seed);
    let p = G1::one();
    let alpha = g1_mul_fr(&p, &a);
    let beta = g1_mul_fr(vehicle_pub, &a);

    let alpha_b = g1_to_compressed(&alpha);
    let beta_b = g1_to_compressed(&beta);

    let k = Sha256::digest(&beta_b);
    let k1 = hkdf_one("k1", &k);
    let k2 = hkdf_one("k2", &k);
    let mac = hmac_sha256(&k2, &alpha_b);
    (RSUBroadcastMsg { alpha_compressed: alpha_b, beta_compressed: beta_b, mac }, k1, k2)
}

pub fn vehicle_process_rsu_handshake(msg: &RSUBroadcastMsg) -> Option<([u8;32], [u8;32])> {
    let k = Sha256::digest(&msg.beta_compressed);
    let k2 = hkdf_one("k2", &k);
    if hmac_sha256(&k2, &msg.alpha_compressed) != msg.mac { return None; }
    let k1 = hkdf_one("k1", &k);
    let k2 = hkdf_one("k2", &k);
    Some((k1, k2))
}

// ---------- V2V Beacon ----------

#[derive(Clone)]
pub struct V2VBeacon {
    pub beta_compressed: [u8;48],
    pub kprime_hint: [u8;32],
    pub cipher: Vec<u8>,
    pub mac: [u8;32],
    pub enc_id_for_ta: Vec<u8>,
    pub sig: [u8;32],         
}

// Send a V2V beacon.

pub fn v2v_beacon_send(
    message: &[u8],
    zone: &ZoneKeys,
    ta: &TAParams,
    sender_id: &str,
    q_vehicle: &G1,
    tpd_seed: &[u8],
) -> V2VBeacon {
    let b = hash_to_fr("tpd-b", tpd_seed);
    let p = G1::one();
    let beta = g1_mul_fr(&p, &b);          // b*P
    let bqb = g1_mul_fr(&zone.q_bcast, &b); // b * Q_bcast

    // --- regular receiver keys ---
    let beta_b = g1_to_compressed(&beta);
    let bqb_b = g1_to_compressed(&bqb);
    let kprime = Sha256::digest(&bqb_b);
    let k1 = hkdf_one("k1'", &kprime);
    let k2 = hkdf_one("k2'", &kprime);
    let nonce = &beta_b[..16];
    let enc = stream_xor_encrypt(&k1, nonce);
    let cipher = enc(message);
    let mac = hmac_sha256(&k2, &cipher);

    // --- encrypted id for TA ---
    let bq_ta = g1_mul_fr(&ta.q_ta, &b); // b * Q_ta
    let bq_ta_b = g1_to_compressed(&bq_ta);
    let k_ta = hkdf_one("k_ta", &Sha256::digest(&bq_ta_b));
    let nonce_ta = &beta_b[..16];
    let enc_for_ta = stream_xor_encrypt(&k_ta, nonce_ta);
    let enc_id = enc_for_ta(sender_id.as_bytes());

    // --- signature visible to TA/public receivers: SHA256(message || Q_vehicle_compressed) ---
    let qv_comp = g1_to_compressed(q_vehicle);
    let mut sig_input = Vec::with_capacity(message.len() + qv_comp.len());
    sig_input.extend_from_slice(message);
    sig_input.extend_from_slice(&qv_comp);
    let sig = Sha256::digest(&sig_input);
    let mut sig_arr = [0u8;32]; sig_arr.copy_from_slice(&sig);

    let mut hint = [0u8;32]; hint.copy_from_slice(&kprime);
    V2VBeacon {
        beta_compressed: beta_b,
        kprime_hint: hint,
        cipher,
        mac,
        enc_id_for_ta: enc_id,
        sig: sig_arr,
    }
}

/// Regular vehicle receiving a beacon (does not decrypt enc_id_for_ta).
pub fn v2v_beacon_recv(beacon: &V2VBeacon, zone: &ZoneKeys) -> Option<Vec<u8>> {
    // Reconstruct b*Q_bcast as d_bcast * beta (since beta = b*P).
    let beta_pt = g1_from_compressed(&beacon.beta_compressed);
    let bqb = g1_mul_fr(&beta_pt, &zone.d_bcast); // = d_bcast * beta = b * Q_bcast
    let bqb_compressed = g1_to_compressed(&bqb);

    let kprime = Sha256::digest(&bqb_compressed);
    let k1 = hkdf_one("k1'", &kprime);
    let k2 = hkdf_one("k2'", &kprime);

    if hmac_sha256(&k2, &beacon.cipher) != beacon.mac { return None; }
    let nonce = &beacon.beta_compressed[..16];
    let dec = stream_xor_encrypt(&k1, nonce);
    Some(dec(&beacon.cipher))
}

// ---------- TA Identity Tracking & Revocation ----------

pub fn ta_identity_tracking_and_revocation(
    ta: &TAParams,
    beacon: &V2VBeacon,
    registry: &mut Registry,
    message: &[u8],
) -> Option<String> {
    // 1. compute k'' = d_ta * beta (beta is b*P; result = b * Q_ta)
    let beta_pt = g1_from_compressed(&beacon.beta_compressed);
    let bq_ta = g1_mul_fr(&beta_pt, &ta.d_ta); // = d_ta * beta = b * Q_ta
    let bq_ta_comp = g1_to_compressed(&bq_ta);

    // 2. derive k1'' = HKDF(1, k'')
    let k1_pp = hkdf_one("k_ta", &Sha256::digest(&bq_ta_comp));

    // 3. decrypt enc_id_for_ta
    let nonce_ta = &beacon.beta_compressed[..16];
    let dec_for_ta = stream_xor_encrypt(&k1_pp, nonce_ta);
    let id_bytes = dec_for_ta(&beacon.enc_id_for_ta);
    let id_str = match String::from_utf8(id_bytes) {
        Ok(s) => s,
        Err(_) => return None,
    };

    // 4. lookup
    let resp = match registry.get(&id_str) {
        Some(r) => r.clone(),
        None => return None,
    };

    let start_re = Instant::now();

    // 5. reconstruct Q_v using ECQV P2
    let q_v = ecqv_compute_public(ta, &resp);
    let q_v_comp = g1_to_compressed(&q_v);

    // 6. verify sig: recompute SHA256(message || Q_v_comp)
    let mut sig_input = Vec::with_capacity(message.len() + q_v_comp.len());
    sig_input.extend_from_slice(message);
    sig_input.extend_from_slice(&q_v_comp);
    let expected_sig = Sha256::digest(&sig_input);
    if expected_sig.as_slice() != beacon.sig {
        return None;
    }

    // mark revoked
    registry.mark_revoked(&id_str);
    let duration_re = start_re.elapsed();
    println!("Revocation time : {:.3} ms", duration_re.as_secs_f64() * 1000.0);

    Some(id_str)
}


fn main() {
    // create TA and registry
    let mut registry = Registry::new();
    let ta = ta_setup(b"ta-seed-ecqv");

    println!("== TA Setup ==");
    println!("P (compressed): {}", hexs::encode(&ta.p_gen_compressed));
    println!("Q_ta (compressed): {}", hexs::encode(&ta.q_ta_compressed));
    println!("d_ta (hex): {}", fr_to_hex(&ta.d_ta));

    // RSU registration (stores in registry)
    let (q_rsu, d_rsu) = rsu_registration(&ta, "RSU-001", &mut registry);
    println!("\n== RSU registered ==");
    println!("Q_rsu (compressed): {}", hexs::encode(g1_to_compressed(&q_rsu)));
    println!("d_rsu (hex): {}", fr_to_hex(&d_rsu));

    // Vehicle registration (stores in registry)
    let (q_vehicle, d_vehicle) = vehicle_registration(&ta, "VEHICLE-001", &mut registry);
    println!("\n== Vehicle registered ==");
    println!("Q_vehicle (compressed): {}", hexs::encode(g1_to_compressed(&q_vehicle)));
    println!("d_vehicle (hex): {}", fr_to_hex(&d_vehicle));

    let start = Instant::now();

    // 5.3.2 handshake / zone keys
    let zone = ta_issue_zone_keys("zone-1");
    let token = ta_daily_handshake(&zone, "RSU-001");
    println!("\n== Daily handshake ==");
    println!("zone={}, ref={}, valid={}s", token.zone, fr_to_hex(&token.ref_no), token.valid_secs);

    // 5.3.3 RSU -> Vehicle
    let (rsu_msg, k1, _k2) = rsu_to_vehicle_handshake(&q_vehicle, b"rsu-ephemeral-seed");
    println!("\nRSU->Vehicle MAC: {}", hexs::encode(&rsu_msg.mac));
    let veh_keys = vehicle_process_rsu_handshake(&rsu_msg).expect("vehicle handshake failed");
    println!("Vehicle derived session keys k1[0..8]={}", hexs::encode(&veh_keys.0)[..8].to_string());

    let duration = start.elapsed();
    println!("Zone Entry Authentication : {:.3} ms", duration.as_secs_f64() * 1000.0);

    // Now create a V2V beacon sent by VEHICLE-001 intended for zone; include enc_id_for_ta and sig
    let payload = b"hazard at GPS(12.34,56.78)";
    let beacon = v2v_beacon_send(payload, &zone, &ta, "VEHICLE-001", &q_vehicle, b"tpd-seed-A");
    println!("\nV2V beacon: beta={}, ctlen={}", hexs::encode(&beacon.beta_compressed), beacon.cipher.len());

    // Regular vehicle receive
    if let Some(pt) = v2v_beacon_recv(&beacon, &zone) {
        println!("V2V received payload: {}", String::from_utf8_lossy(&pt));
    } else {
        println!("V2V MAC check failed");
    }

    // TA receives a dispute request containing the beacon and message; TA runs identity tracking & revocation
    if let Some(found_id) = ta_identity_tracking_and_revocation(&ta, &beacon, &mut registry, payload) {
        println!("TA recovered id: {} and has revoked it.", found_id);
    } else {
        println!("TA could not recover/verify identity from the beacon for dispute resolution.");
    }

    // show registry revoked set
    println!("Registry revoked list: {:?}", registry.revoked);

}
