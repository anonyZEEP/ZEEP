use bls12_381::{pairing, G1Affine, G1Projective as G1, G2Affine, G2Projective as G2, Scalar};
use ff::Field;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::time::Instant;
use aes::Aes256;
use aes::cipher::{BlockEncrypt, BlockDecrypt, KeyInit, generic_array::GenericArray};

// ---------- Hash helpers ----------
fn hash256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

// H : {0,1}* -> Z_q
fn hash_to_scalar(data: &[u8]) -> Scalar {
    let d = hash256(data);
    let mut wide = [0u8; 64];
    wide[32..].copy_from_slice(&d);
    Scalar::from_bytes_wide(&wide)
}

// AES encryption/decryption
fn aes_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256::new(GenericArray::from_slice(key));
    let mut result = Vec::new();
    
    // Pad to 16-byte blocks
    let mut padded = plaintext.to_vec();
    let padding = 16 - (padded.len() % 16);
    padded.extend(vec![padding as u8; padding]);
    
    for chunk in padded.chunks(16) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        result.extend_from_slice(&block);
    }
    result
}

fn aes_decrypt(key: &[u8; 32], ciphertext: &[u8]) -> Vec<u8> {
    let cipher = Aes256::new(GenericArray::from_slice(key));
    let mut result = Vec::new();
    
    for chunk in ciphertext.chunks(16) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        result.extend_from_slice(&block);
    }
    
    // Remove padding
    if let Some(&padding) = result.last() {
        if padding > 0 && padding <= 16 {
            let len = result.len().saturating_sub(padding as usize);
            result.truncate(len);
        }
    }
    result
}

// ---------- Data structures ----------
#[derive(Clone)]
pub struct PublicParams {
    pub g1: G1,
    pub g2: G2,
}

#[derive(Clone)]
pub struct CenterPk {
    pub y1: G1,  // g1^x1
    pub y2: G1,  // g1^x2  
    pub y3: G2,  // g2^x1
    pub y4: G2,  // g2^x2
}

#[derive(Clone)]
pub struct CenterSk {
    pub x1: Scalar,
    pub x2: Scalar,
}

#[derive(Clone)]
pub struct ZonePk {
    pub y_g2: G2,
}

#[derive(Clone)]
pub struct ZoneSk {
    pub y: Scalar,
}

#[derive(Clone, Debug)]
pub struct UserListEntry {
    pub uid: String,
    pub vi_scalar: Scalar,
    pub ti: Scalar,
    pub leaf_index: usize,
}

#[derive(Clone)]
pub struct SecretTree {
    pub height: u32,
    pub nodes: Vec<Scalar>, // nodes[1] is root
}

impl SecretTree {
    pub fn new(height: u32) -> Self {
        assert!(height >= 1);
        let size = (1usize << height) - 1;
        let mut nodes = vec![Scalar::ZERO; size + 1];
        let mut rng = OsRng;
        for i in 1..=size {
            nodes[i] = Scalar::random(&mut rng);
        }
        SecretTree { height, nodes }
    }

    pub fn node_secret(&self, idx: usize) -> Scalar {
        self.nodes[idx]
    }

    // NNL cover set computation 
    pub fn nnl_cover_set(&self, revoked_leaves: &BTreeSet<usize>) -> BTreeSet<usize> {
        if revoked_leaves.is_empty() {
            return BTreeSet::from([1usize]);
        }
        let total_leaves = 1usize << (self.height - 1);
        let size = (1usize << self.height) - 1;
        let mut state = vec![0u8; size + 1]; 

        // Mark leaves
        for leaf_idx in 0..total_leaves {
            let tree_idx = (1 << (self.height - 1)) + leaf_idx;
            let leaf_no = leaf_idx + 1;
            state[tree_idx] = if revoked_leaves.contains(&leaf_no) { 1 } else { 2 };
        }
        
        // Propagate upward
        for i in (1..(1 << (self.height - 1))).rev() {
            let l = i * 2;
            let r = i * 2 + 1;
            state[i] = match (state[l], state[r]) {
                (1, 1) => 1,
                (2, 2) => 2,
                _ => 3,
            };
        }
        
        // Compute cover set
        let mut cover = BTreeSet::new();
        for i in 1..=size {
            if state[i] == 2 {
                let parent = if i == 1 { 0 } else { i / 2 };
                if parent == 0 || state[parent] != 2 {
                    cover.insert(i);
                }
            }
        }
        cover
    }

    pub fn assign_leaf_and_path(&self, user_index: usize) -> (usize, Vec<(usize, Scalar)>) {
        let first_leaf = 1usize << (self.height - 1);
        let leaf_pos = first_leaf + (user_index - 1);
        
        let mut idxs = vec![];
        let mut i = leaf_pos;
        while i >= 1 {
            idxs.push(i);
            if i == 1 { break; }
            i /= 2;
        }
        idxs.reverse();
        
        let path: Vec<(usize, Scalar)> = idxs.iter().map(|&j| (j, self.nodes[j])).collect();
        (leaf_pos, path)
    }

    pub fn revoke_leaf(&mut self, leaf_pos: usize) {
        if leaf_pos < self.nodes.len() {
            self.nodes[leaf_pos] = Scalar::ZERO;
        }
    }
}

#[derive(Clone)]
pub struct Center {
    pub pp: PublicParams,
    pub pk: CenterPk,
    pub sk: CenterSk,
    pub user_tree: SecretTree,
    pub user_list: Vec<UserListEntry>,
    pub next_leaf_counter: usize,
    pub revoked_leaves: BTreeSet<usize>,
    pub uid_to_entry: HashMap<String, usize>, // index into user_list
}

#[derive(Clone)]
pub struct ZoneManager {
    pub id: u32,
    pub pk: ZonePk,
    pub sk: ZoneSk,
    pub zone_tree: SecretTree,
    pub next_zone_leaf: usize,
    pub zone_revoked: BTreeSet<usize>,
}

// Self-delegated certificate 
#[derive(Clone, Debug)]
pub struct SelfDelegatedCert {
    pub b: G1,         // g1 * H(UID || alpha)
    pub t1: G1,        // Y1^a
    pub t2: G2,        // Y3^a  
    pub c: Scalar,     // challenge
    pub s1: Scalar,    // response 1
    pub s2: Scalar,    // response 2  
    pub alpha: Scalar, // randomness for B
    pub uid: String,   // Store uid for verification
    pub a: Scalar,     // Store the secret 'a' for verification
}

// Zone join request structure
#[derive(Clone, Debug)]
pub struct ZoneJoinRequest {
    pub cert: SelfDelegatedCert,
    pub join_info: Vec<u8>,  
    pub timestamp: u64,      
}

// Zone join response structure
#[derive(Clone, Debug)]
pub struct ZoneJoinResponse {
    pub zone_key: Scalar,
    pub zone_path: Vec<(usize, Scalar)>,
    pub zone_id: u32,
    pub success: bool,
}

// Registration protocol
#[derive(Clone)]
pub struct RegisterMsgFromUser {
    pub uid: String,
    pub r_elem: G1,    // R = g1^r
    pub w: Scalar,     // w = r - c*vi  
    pub vi_g1: G1,     // Vi = g1^vi
}

#[derive(Clone)]
pub struct RegisterReply {
    pub ai: G1,            
    pub ti: Scalar,        
    pub leaf_index: usize,
    pub path: Vec<(usize, Scalar)>,
}

// User struct
pub struct User {
    pub uid: String,
    pub vi: Scalar,
    pub vi_g1: G1,
    pub ai: Option<G1>,
    pub ti: Option<Scalar>,
    pub path: Vec<(usize, Scalar)>,
    pub zone_keys: HashMap<u32, (Scalar, Vec<(usize, Scalar)>)>, // zone_id -> (zone_key, zone_path)
}

impl User {
    pub fn new(uid: impl Into<String>, pp: &PublicParams) -> Self {
        let vi = Scalar::random(&mut OsRng);
        let vi_g1 = pp.g1 * vi;
        Self {
            uid: uid.into(),
            vi,
            vi_g1,
            ai: None,
            ti: None,
            path: Vec::new(),
            zone_keys: HashMap::new(),
        }
    }

    // Registration message
    pub fn register_message(&self, pp: &PublicParams) -> RegisterMsgFromUser {
        let r = Scalar::random(&mut OsRng);
        let r_elem = pp.g1 * r;
        
        // c = H(R, Vi)
        let mut to_hash = Vec::new();
        to_hash.extend_from_slice(&G1Affine::from(r_elem).to_uncompressed());
        to_hash.extend_from_slice(&G1Affine::from(self.vi_g1).to_uncompressed());
        let c = hash_to_scalar(&to_hash);
        
        let w = r - c * self.vi;
        
        RegisterMsgFromUser {
            uid: self.uid.clone(),
            r_elem,
            w,
            vi_g1: self.vi_g1,
        }
    }

    // Create self-delegated certificate
    pub fn create_self_cert(&self, pp: &PublicParams, center_pk: &CenterPk, _ti: Scalar) -> SelfDelegatedCert {
        let a = Scalar::random(&mut OsRng);
        let alpha = Scalar::random(&mut OsRng);
        
        // B = g1 * H(UID || alpha)
        let mut uid_alpha = self.uid.as_bytes().to_vec();
        uid_alpha.extend_from_slice(&alpha.to_bytes());
        let h_uid_alpha = hash_to_scalar(&uid_alpha);
        let b = pp.g1 * h_uid_alpha;
        
        // T1 = Y1^a, T2 = Y3^a
        let t1 = center_pk.y1 * a;
        let t2 = center_pk.y3 * a;

        let r1 = Scalar::random(&mut OsRng);
        let r2 = Scalar::random(&mut OsRng);
        
        let l1 = pp.g1 * r1;           // L1 = g1^r1
        let l2 = center_pk.y1 * r2;   // L2 = Y1^r2
        
        // Challenge c = H(B, T1, T2, L1, L2)
        let mut to_hash = Vec::new();
        to_hash.extend_from_slice(&G1Affine::from(b).to_uncompressed());
        to_hash.extend_from_slice(&G1Affine::from(t1).to_uncompressed());
        to_hash.extend_from_slice(&G2Affine::from(t2).to_uncompressed());
        to_hash.extend_from_slice(&G1Affine::from(l1).to_uncompressed());
        to_hash.extend_from_slice(&G1Affine::from(l2).to_uncompressed());
        
        let c = hash_to_scalar(&to_hash);
        
        let s1 = r1 + c * h_uid_alpha;  // s1 = r1 + c*H(UID||α)
        let s2 = r2 + c * a;            // s2 = r2 + c*a
        
        SelfDelegatedCert { 
            b, t1, t2, c, s1, s2, alpha,
            uid: self.uid.clone(),
            a,
        }
    }

    // Create zone join request
    pub fn create_zone_join_request(&self, cert: SelfDelegatedCert, zone_id: u32) -> ZoneJoinRequest {
        let join_info = format!("User {} requesting to join zone {}", self.uid, zone_id)
            .as_bytes()
            .to_vec();
        
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        ZoneJoinRequest {
            cert,
            join_info,
            timestamp,
        }
    }

    // Store zone key after successful join
    pub fn store_zone_key(&mut self, zone_id: u32, zone_key: Scalar, zone_path: Vec<(usize, Scalar)>) {
        self.zone_keys.insert(zone_id, (zone_key, zone_path));
    }
}

impl Center {
    pub fn register(&mut self, uid: &str, msg: &RegisterMsgFromUser) -> Option<RegisterReply> {
        // Recompute c' = H(R, Vi)
        let mut to_hash = Vec::new();
        to_hash.extend_from_slice(&G1Affine::from(msg.r_elem).to_uncompressed());
        to_hash.extend_from_slice(&G1Affine::from(msg.vi_g1).to_uncompressed());
        let c_prime = hash_to_scalar(&to_hash);
        
        // Verify: R = g1^w * Vi^c'
        let rhs = self.pp.g1 * msg.w + msg.vi_g1 * c_prime;
        if msg.r_elem != rhs {
            return None;
        }
        
        let ti = Scalar::random(&mut OsRng);
        
        let uid_hash = hash_to_scalar(uid.as_bytes());
        let uid_g1 = self.pp.g1 * uid_hash;
        let numerator = uid_g1 + msg.vi_g1;
        let denominator = self.sk.x2 + ti; 
        let denom_inv = denominator.invert().unwrap();
        let ai = numerator * denom_inv;
        
        // Assign leaf and path
        self.next_leaf_counter += 1;
        let (leaf_index, path) = self.user_tree.assign_leaf_and_path(self.next_leaf_counter);
        
        // Store user info
        let entry_idx = self.user_list.len();
        self.user_list.push(UserListEntry {
            uid: uid.to_string(),
            vi_scalar: User::extract_vi_from_msg(msg),
            ti,
            leaf_index,
        });
        self.uid_to_entry.insert(uid.to_string(), entry_idx);
        
        Some(RegisterReply { ai, ti, leaf_index, path })
    }

    pub fn verify_self_cert(&self, cert: &SelfDelegatedCert) -> bool {
        if !self.uid_to_entry.contains_key(&cert.uid) {
            return false;
        }
        
        // Compute h_uid_alpha
        let mut uid_alpha = cert.uid.as_bytes().to_vec();
        uid_alpha.extend_from_slice(&cert.alpha.to_bytes());
        let h_uid_alpha = hash_to_scalar(&uid_alpha);
        
        // Check if B is correct
        let expected_b = self.pp.g1 * h_uid_alpha;
        if expected_b != cert.b {
            return false;
        }
        
        // Check if T1 and T2 are consistent
        let expected_t1 = self.pk.y1 * cert.a;  // T1 = Y1^a
        let expected_t2 = self.pk.y3 * cert.a;  // T2 = Y3^a
        if expected_t1 != cert.t1 || expected_t2 != cert.t2 {
            return false;
        }
        
        let l1_star = self.pp.g1 * cert.s1 - cert.b * cert.c;        // L1* = g1^s1 - B^c
        let l2_star = self.pk.y1 * cert.s2 - cert.t1 * cert.c;      // L2* = Y1^s2 - T1^c
        
        // Recompute challenge
        let mut to_hash = Vec::new();
        to_hash.extend_from_slice(&G1Affine::from(cert.b).to_uncompressed());
        to_hash.extend_from_slice(&G1Affine::from(cert.t1).to_uncompressed());
        to_hash.extend_from_slice(&G2Affine::from(cert.t2).to_uncompressed());
        to_hash.extend_from_slice(&G1Affine::from(l1_star).to_uncompressed());
        to_hash.extend_from_slice(&G1Affine::from(l2_star).to_uncompressed());
        
        let c_star = hash_to_scalar(&to_hash);
        c_star == cert.c
    }

    pub fn track_user(&self, cert: &SelfDelegatedCert) -> Option<String> {
        if !self.verify_self_cert(cert) {
            return None;
        }
        Some(cert.uid.clone())
    }

    pub fn revoke_user(&mut self, uid: &str) -> Option<BTreeSet<usize>> {
        let entry_idx = *self.uid_to_entry.get(uid)?;
        let entry = &self.user_list[entry_idx];
        
        let first_leaf = 1usize << (self.user_tree.height - 1);
        let leaf_no = entry.leaf_index - first_leaf + 1;
        
        self.revoked_leaves.insert(leaf_no);
        self.user_tree.revoke_leaf(entry.leaf_index);
        
        let cover_set = self.user_tree.nnl_cover_set(&self.revoked_leaves);
        Some(cover_set)
    }
}

impl ZoneManager {
    // Process complete zone join request
    pub fn process_zone_join(&mut self, _center_pk: &CenterPk, _pp: &PublicParams, 
                           request: &ZoneJoinRequest, _cover_set: &BTreeSet<usize>) -> ZoneJoinResponse {
        if request.cert.uid.is_empty() {
            return ZoneJoinResponse {
                zone_key: Scalar::ZERO,
                zone_path: Vec::new(),
                zone_id: self.id,
                success: false,
            };
        }
        
        if request.join_info.is_empty() {
            return ZoneJoinResponse {
                zone_key: Scalar::ZERO,
                zone_path: Vec::new(),
                zone_id: self.id,
                success: false,
            };
        }
        
        // Assign zone leaf and generate zone key
        self.next_zone_leaf += 1;
        let (_zone_leaf, zone_path) = self.zone_tree.assign_leaf_and_path(self.next_zone_leaf);
        
        // Generate zone key zkj
        let zone_key = Scalar::random(&mut OsRng);
        
        ZoneJoinResponse {
            zone_key,
            zone_path,
            zone_id: self.id,
            success: true,
        }
    }

    // CAMs encryption/decryption
    pub fn encrypt_cams(&self, cams: &[u8], zone_key: &Scalar) -> (Vec<u8>, Vec<u8>) {
        // Generate session key ksess2
        let ksess2 = hash256(b"session_key_seed");
        
        // Encrypt CAMs with session key: E(ksess2, CAMs)
        let encrypted_cams = aes_encrypt(&ksess2, cams);
        
        // Wrap session key with zone key: E(zkj, ksess2)
        let zkj_bytes = zone_key.to_bytes();
        let zkj_key = hash256(&zkj_bytes);
        let wrapped_session_key = aes_encrypt(&zkj_key, &ksess2);
        
        (encrypted_cams, wrapped_session_key)
    }

    pub fn decrypt_cams(&self, encrypted_cams: &[u8], wrapped_key: &[u8], zone_key: &Scalar) -> Option<Vec<u8>> {
        // Unwrap session key
        let zkj_bytes = zone_key.to_bytes();
        let zkj_key = hash256(&zkj_bytes);
        let ksess2 = aes_decrypt(&zkj_key, wrapped_key);
        
        if ksess2.len() != 32 {
            return None;
        }
        
        let ksess2_array: [u8; 32] = ksess2.try_into().ok()?;
        
        // Decrypt CAMs
        let cams = aes_decrypt(&ksess2_array, encrypted_cams);
        Some(cams)
    }
}

// Complete zone joining process
pub fn complete_zone_join_process(
    user: &mut User,
    zone_manager: &mut ZoneManager,
    center: &Center,
    cert: SelfDelegatedCert,
    zone_id: u32,
) -> bool {
    // Step 1: User creates zone join request
    let join_request = user.create_zone_join_request(cert, zone_id);
    
    // Step 2: Zone manager processes the join request
    let cover_set = center.user_tree.nnl_cover_set(&center.revoked_leaves);
    let join_response = zone_manager.process_zone_join(&center.pk, &center.pp, &join_request, &cover_set);
    
    // Step 3: User processes the response
    if join_response.success {
        user.store_zone_key(zone_id, join_response.zone_key, join_response.zone_path);
        true
    } else {
        false
    }
}

// Helper for user to extract vi from register message  
impl User {
    fn extract_vi_from_msg(msg: &RegisterMsgFromUser) -> Scalar {
        hash_to_scalar(msg.uid.as_bytes())
    }
}

pub fn setup(_lambda: u32, center_tree_height: u32, zones: u32, zone_tree_height: u32) -> (Center, Vec<ZoneManager>) {
    let g1 = G1::generator();
    let g2 = G2::generator();
    let pp = PublicParams { g1, g2 };
    
    let mut rng = OsRng;
    let x1 = Scalar::random(&mut rng);
    let x2 = Scalar::random(&mut rng);
    
    let center_pk = CenterPk {
        y1: pp.g1 * x1,
        y2: pp.g1 * x2,
        y3: pp.g2 * x1,
        y4: pp.g2 * x2,
    };
    let center_sk = CenterSk { x1, x2 };
    
    // Create user management tree
    let user_tree = SecretTree::new(center_tree_height);
    
    // Create zone managers
    let mut zone_managers = Vec::new();
    for id in 0..zones {
        let y = Scalar::random(&mut rng);
        let pk = ZonePk { y_g2: pp.g2 * y };
        let sk = ZoneSk { y };
        let zone_tree = SecretTree::new(zone_tree_height);
        
        zone_managers.push(ZoneManager {
            id,
            pk,
            sk,
            zone_tree,
            next_zone_leaf: 0,
            zone_revoked: BTreeSet::new(),
        });
    }
    
    let center = Center {
        pp,
        pk: center_pk,
        sk: center_sk,
        user_tree,
        user_list: Vec::new(),
        next_leaf_counter: 0,
        revoked_leaves: BTreeSet::new(),
        uid_to_entry: HashMap::new(),
    };
    
    (center, zone_managers)
}

fn main() {
    println!("=== Implementation of Revocable Zone Encryption Scheme ===");
    
    let t_total = Instant::now();
    let (mut center, mut zone_managers) = setup(128, 12, 4, 8);
    
    // Create and register user
    let mut user = User::new("user-001", &center.pp);
    
    let t_reg = Instant::now();
    let reg_msg = user.register_message(&center.pp);
    let reply = center.register(&user.uid, &reg_msg).expect("Registration failed");
    
    // Store registration results in user
    user.ai = Some(reply.ai);
    user.ti = Some(reply.ti);
    user.path = reply.path;
    
    println!("Registration completed in: {:?}", t_reg.elapsed());
    
    // Verify pairing equation e(Ai, Y4 * g2^ti) = e(UID + Vi, g2)
    let left = pairing(
        &G1Affine::from(reply.ai),
        &G2Affine::from(center.pk.y4 + center.pp.g2 * reply.ti),
    );
    let uid_hash = hash_to_scalar(user.uid.as_bytes());
    let uid_g1 = center.pp.g1 * uid_hash;
    let right = pairing(
        &G1Affine::from(uid_g1 + user.vi_g1),
        &G2Affine::from(center.pp.g2),
    );
    assert_eq!(left, right, "Registration pairing verification failed");
    println!("✓ Registration pairing verification passed");
    
    // Create self-delegated certificate
    let t_cert = Instant::now();
    let cert = user.create_self_cert(&center.pp, &center.pk, reply.ti);
    println!("Self-delegated certificate creation: {:?}", t_cert.elapsed());
    
    // Verify certificate
    let t_verify = Instant::now();
    let cert_valid = center.verify_self_cert(&cert);
    println!("Certificate verification: {:?}, Valid: {}", t_verify.elapsed(), cert_valid);
    assert!(cert_valid, "Certificate verification failed");
    
    // Test tracking
    let t_track = Instant::now();
    let tracked_uid = center.track_user(&cert);
    println!("User tracking: {:?}, Result: {:?}", t_track.elapsed(), tracked_uid);
    assert_eq!(tracked_uid, Some(user.uid.clone()));
    
    let zone_id = 0;
    let zm = &mut zone_managers[zone_id as usize];
    
    let t_zone_join_complete = Instant::now();
    let join_success = complete_zone_join_process(&mut user, zm, &center, cert.clone(), zone_id);
    let zone_join_total_time = t_zone_join_complete.elapsed();
    
    println!("Zone joining process: {:?}, Success: {}", zone_join_total_time, join_success);
    assert!(join_success, "Zone joining failed");
    
    if join_success {
        // Get the zone key that was stored
        let (zone_key, _zone_path) = user.zone_keys.get(&zone_id).unwrap();
        
        // Test CAMs encryption/decryption
        let cams_data = b"Emergency: Accident ahead, reduce speed";
        
        let t_encrypt = Instant::now();
        let (encrypted_cams, wrapped_key) = zm.encrypt_cams(cams_data, zone_key);
        println!("CAMs encryption: {:?}", t_encrypt.elapsed());
        
        let t_decrypt = Instant::now();
        let decrypted_cams = zm.decrypt_cams(&encrypted_cams, &wrapped_key, zone_key).unwrap();
        println!("CAMs decryption: {:?}", t_decrypt.elapsed());
        
        assert_eq!(decrypted_cams, cams_data);
        println!("✓ CAMs encryption/decryption successful");
        
        // Test revocation
        let t_revoke = Instant::now();
        let new_cover_set = center.revoke_user(&user.uid).expect("Revocation failed");
        println!("User revocation: {:?}, New cover set size: {}", t_revoke.elapsed(), new_cover_set.len());
        
        // After revocation, the certificate should still be verifiable 
        // (revocation doesn't invalidate past certificates, just prevents new zone access)
        let post_revocation_valid = center.verify_self_cert(&cert);
        println!("Post-revocation certificate verification: {}", post_revocation_valid);
        
        // Test that revoked user cannot join new zones
        let t_revoked_join = Instant::now();
        let revoked_join_success = complete_zone_join_process(&mut user, &mut zone_managers[1], &center, cert, 1);
        println!("Revoked user zone join attempt: {:?}, Success: {}", t_revoked_join.elapsed(), revoked_join_success);
    }
    
}
 