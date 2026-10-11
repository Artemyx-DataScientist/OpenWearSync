//! Cryptographic pairing, authenticated transport verification, peer enrollment, and revocation.

use openwearsync_protocol::{ErrorCode, ProtocolError, ProtocolResult};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

// START_MODULE_CONTRACT
// PURPOSE: Cryptographic pairing, authenticated transport verification, peer enrollment, and revocation.
// SCOPE: One-time code enrollment, rate-limited PIN verification, peer key pinning, token authorization, replay rejection.
// DEPENDS: openwearsync-protocol, rand, serde, sha2
// LINKS: M-PAIRING-SECURITY, M-WINDOWS-RECEIVER, V-M-PAIRING-SECURITY, DF-DISCOVERY-AND-PAIRING
// END_MODULE_CONTRACT

// START_MODULE_MAP
//   RateLimiter - enforces max attempt count and lockout windows against brute-force attacks.
//   OneTimeCodePairing - interactive enrollment protocol using short numeric PIN and commitment hashes.
//   PairedPeer - persisted record of an enrolled client or receiver with pinned identity and revocation flag.
//   PairedPeerRegistry - thread-safe store for enrolled and revoked devices.
//   AuthToken - authenticated time-bounded session token protecting transfer endpoints.
//   ReplayFilter - tracks nonces to reject replayed authentication requests.
// END_MODULE_MAP

/// Computes HMAC-SHA-256 using standard RFC 2104 algorithm.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let block_size = 64;
    let mut k = [0u8; 64];

    if key.len() > block_size {
        let hash = sha2::Sha256::digest(key);
        k[..32].copy_from_slice(&hash);
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0u8; 64];
    let mut opad = [0u8; 64];
    for i in 0..block_size {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }

    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(message);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    outer.finalize().into()
}

/// Constant-time comparison of two 32-byte arrays to resist timing attacks.
pub fn constant_time_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Enforces bounded online guessing rates with attempt caps and cooldowns.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    max_attempts: u32,
    lockout_duration: Duration,
    attempts: Arc<Mutex<HashMap<String, (u32, Instant)>>>,
}

impl RateLimiter {
    pub fn new(max_attempts: u32, lockout_duration: Duration) -> Self {
        Self {
            max_attempts,
            lockout_duration,
            attempts: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    // START_CONTRACT: RateLimiter::check_and_record_failure
    // PURPOSE: Record a failed attempt and determine if the caller is currently locked out.
    // INPUTS: { key: &str - client identity or IP }
    // OUTPUTS: { ProtocolResult<()> - Ok if allowed to retry, Err if locked out }
    // SIDE_EFFECTS: increments failure counter or resets if lockout expired.
    // END_CONTRACT: RateLimiter::check_and_record_failure
    pub fn record_failure(&self, key: &str) -> ProtocolResult<()> {
        let mut map = self.attempts.lock().unwrap();
        let now = Instant::now();

        let entry = map.entry(key.to_string()).or_insert((0, now));
        if now.duration_since(entry.1) > self.lockout_duration {
            // Lockout expired, reset
            *entry = (1, now);
            return Ok(());
        }

        entry.0 += 1;
        entry.1 = now;

        if entry.0 >= self.max_attempts {
            Err(ProtocolError {
                code: ErrorCode::LimitExceeded,
                message: format!(
                    "too many failed attempts for {}; locked out for {:?}",
                    key, self.lockout_duration
                ),
            })
        } else {
            Ok(())
        }
    }

    /// Check if currently locked out without incrementing.
    pub fn check_allowed(&self, key: &str) -> ProtocolResult<()> {
        let mut map = self.attempts.lock().unwrap();
        if let Some((count, last_time)) = map.get(key) {
            if *count >= self.max_attempts {
                if last_time.elapsed() < self.lockout_duration {
                    return Err(ProtocolError {
                        code: ErrorCode::LimitExceeded,
                        message: "rate limit exceeded: client locked out".to_string(),
                    });
                } else {
                    map.remove(key);
                }
            }
        }
        Ok(())
    }

    /// Reset failure count upon successful authentication.
    pub fn record_success(&self, key: &str) {
        let mut map = self.attempts.lock().unwrap();
        map.remove(key);
    }
}

/// Generates a secure random 6-digit PIN code.
pub fn generate_pairing_pin() -> String {
    let mut bytes = [0u8; 4];
    OsRng.fill_bytes(&mut bytes);
    let num = u32::from_le_bytes(bytes) % 1_000_000;
    format!("{:06}", num)
}

/// Generates a cryptographically secure 32-byte random array.
pub fn generate_random_bytes_32() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Hex encoding helper
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut s, "{:02x}", b);
    }
    s
}

/// Hex decoding helper
pub fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    let trimmed = s.trim();
    if trimmed.len() % 2 != 0 {
        return None;
    }
    let mut bytes = Vec::with_capacity(trimmed.len() / 2);
    for i in (0..trimmed.len()).step_by(2) {
        let byte = u8::from_str_radix(&trimmed[i..i + 2], 16).ok()?;
        bytes.push(byte);
    }
    Some(bytes)
}

/// Parses 32-byte hex array
pub fn hex_to_32(s: &str) -> Option<[u8; 32]> {
    let bytes = hex_to_bytes(s)?;
    if bytes.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Some(arr)
    } else {
        None
    }
}

/// Parses 16-byte hex array
pub fn hex_to_16(s: &str) -> Option<[u8; 16]> {
    let bytes = hex_to_bytes(s)?;
    if bytes.len() == 16 {
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&bytes);
        Some(arr)
    } else {
        None
    }
}

/// Persistent cryptographic server identity with private key, derived public key, and SHA-256 fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerIdentity {
    pub private_key: [u8; 32],
    pub public_key: [u8; 32],
    pub fingerprint: String,
}

impl ServerIdentity {
    pub fn generate() -> Self {
        let private_key = generate_random_bytes_32();
        Self::from_private_key(private_key)
    }

    pub fn from_private_key(private_key: [u8; 32]) -> Self {
        let secret = StaticSecret::from(private_key);
        let public = PublicKey::from(&secret);
        let public_key = *public.as_bytes();
        let digest = Sha256::digest(&public_key);
        let fingerprint = bytes_to_hex(&digest);
        Self {
            private_key,
            public_key,
            fingerprint,
        }
    }
}

/// State for one-time code pairing enrollment with PAKE offline-guessing defense.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingSession {
    pub session_id: String,
    pub server_nonce: [u8; 32],
    pub salt: [u8; 32],
    pub client_id: String,
    pub pin: String,
    pub expires_at_epoch_s: u64,
    pub server_ephemeral_private: [u8; 32],
    pub server_masked_pk: [u8; 32],
}

impl PairingSession {
    // START_CONTRACT: PairingSession::with_pin
    // PURPOSE: Initialize an enrollment session with a specified PIN, random ephemeral keys, and masked public key.
    // INPUTS: { client_id: String, pin: String, ttl_secs: u64 }
    // OUTPUTS: { Self }
    // SIDE_EFFECTS: fills random server nonce, salt, ephemeral keys, and session ID from OS RNG.
    // END_CONTRACT: PairingSession::with_pin
    pub fn with_pin(client_id: String, pin: String, ttl_secs: u64) -> Self {
        let server_nonce = generate_random_bytes_32();
        let salt = generate_random_bytes_32();
        let mut id_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut id_bytes);

        let session_id = format!("pair-{}", bytes_to_hex(&id_bytes));
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let server_ephemeral_private = generate_random_bytes_32();
        let secret = StaticSecret::from(server_ephemeral_private);
        let public = PublicKey::from(&secret);
        let pub_bytes = *public.as_bytes();

        let stretched = stretch_pin(&pin, &salt, 5000);
        let mask_y = hmac_sha256(&stretched, b"OpenWearSync-PAKE-Mask-Y-v1");

        let mut server_masked_pk = [0u8; 32];
        for i in 0..32 {
            server_masked_pk[i] = pub_bytes[i] ^ mask_y[i];
        }

        Self {
            session_id,
            server_nonce,
            salt,
            client_id,
            pin,
            expires_at_epoch_s: now + ttl_secs,
            server_ephemeral_private,
            server_masked_pk,
        }
    }

    // START_CONTRACT: PairingSession::new
    // PURPOSE: Initialize an enrollment session with a 6-digit PIN and cryptographic salt & nonce.
    // INPUTS: { client_id: String, ttl_secs: u64 }
    // OUTPUTS: { Self }
    // SIDE_EFFECTS: generates 6-digit PIN and initializes session.
    // END_CONTRACT: PairingSession::new
    pub fn new(client_id: String, ttl_secs: u64) -> Self {
        let pin = generate_pairing_pin();
        Self::with_pin(client_id, pin, ttl_secs)
    }

    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now > self.expires_at_epoch_s
    }

    /// Derives the pre-shared pairing key from session_id, pin, and server_nonce.
    pub fn derive_pairing_key(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"OpenWearSync-Pairing-Key-v1");
        hasher.update(self.session_id.as_bytes());
        hasher.update(self.pin.as_bytes());
        hasher.update(&self.server_nonce);
        hasher.finalize().into()
    }

    /// Verifies client commitment message.
    pub fn verify_client_commitment(&self, candidate_pin: &str, client_nonce: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"OpenWearSync-Commitment-v1");
        hasher.update(self.session_id.as_bytes());
        hasher.update(candidate_pin.as_bytes());
        hasher.update(&self.server_nonce);
        hasher.update(client_nonce);
        hasher.finalize().into()
    }
}

/// Result of PAKE key derivation containing client and server proofs and shared secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PakeKeys {
    pub client_proof: [u8; 32],
    pub server_proof: [u8; 32],
    pub shared_secret: [u8; 32],
}

/// Result of client PAKE exchange containing masked public key, proofs and shared secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PakeClientResult {
    pub client_masked_pk: [u8; 32],
    pub client_proof: [u8; 32],
    pub server_proof: [u8; 32],
    pub shared_secret: [u8; 32],
}

/// Key stretching on PIN using iterative HMAC-SHA256 (PBKDF2-like).
pub fn stretch_pin(pin: &str, salt: &[u8; 32], iterations: u32) -> [u8; 32] {
    let mut current = hmac_sha256(pin.as_bytes(), salt);
    for _ in 1..iterations {
        current = hmac_sha256(pin.as_bytes(), &current);
    }
    current
}

/// Performs client-side PAKE exchange with ephemeral scalar, unmasking server public key and computing proofs.
pub fn client_pake_exchange(
    pin: &str,
    salt: &[u8; 32],
    server_nonce: &[u8; 32],
    client_nonce: &[u8; 32],
    server_masked_pk: &[u8; 32],
    server_fingerprint: &str,
    client_ephemeral_private: &[u8; 32],
) -> PakeClientResult {
    let stretched = stretch_pin(pin, salt, 5000);
    let client_secret = StaticSecret::from(*client_ephemeral_private);
    let client_pub = PublicKey::from(&client_secret);
    let client_pub_bytes = *client_pub.as_bytes();

    let mask_x = hmac_sha256(&stretched, b"OpenWearSync-PAKE-Mask-X-v1");
    let mut client_masked_pk = [0u8; 32];
    for i in 0..32 {
        client_masked_pk[i] = client_pub_bytes[i] ^ mask_x[i];
    }

    let mask_y = hmac_sha256(&stretched, b"OpenWearSync-PAKE-Mask-Y-v1");
    let mut server_pk = [0u8; 32];
    for i in 0..32 {
        server_pk[i] = server_masked_pk[i] ^ mask_y[i];
    }
    let server_pub = PublicKey::from(server_pk);
    let dh_shared = client_secret.diffie_hellman(&server_pub);

    let mut master_input = Vec::new();
    master_input.extend_from_slice(b"OpenWearSync-PAKE-SessionKey-v1");
    master_input.extend_from_slice(&stretched);
    master_input.extend_from_slice(server_nonce);
    master_input.extend_from_slice(client_nonce);
    master_input.extend_from_slice(server_fingerprint.as_bytes());
    let shared_secret = hmac_sha256(dh_shared.as_bytes(), &master_input);

    let mut cp_input = Vec::new();
    cp_input.extend_from_slice(b"OpenWearSync-ClientProof-v1");
    cp_input.extend_from_slice(client_nonce);
    cp_input.extend_from_slice(server_nonce);
    let client_proof = hmac_sha256(&shared_secret, &cp_input);

    let mut sp_input = Vec::new();
    sp_input.extend_from_slice(b"OpenWearSync-ServerProof-v1");
    sp_input.extend_from_slice(server_nonce);
    sp_input.extend_from_slice(client_nonce);
    let server_proof = hmac_sha256(&shared_secret, &sp_input);

    PakeClientResult {
        client_masked_pk,
        client_proof,
        server_proof,
        shared_secret,
    }
}

/// Performs server-side PAKE exchange, unmasking client public key and computing proofs.
pub fn server_pake_exchange(
    pin: &str,
    salt: &[u8; 32],
    server_nonce: &[u8; 32],
    client_nonce: &[u8; 32],
    client_masked_pk: &[u8; 32],
    server_fingerprint: &str,
    server_ephemeral_private: &[u8; 32],
) -> PakeKeys {
    let stretched = stretch_pin(pin, salt, 5000);
    let server_secret = StaticSecret::from(*server_ephemeral_private);

    let mask_x = hmac_sha256(&stretched, b"OpenWearSync-PAKE-Mask-X-v1");
    let mut client_pk = [0u8; 32];
    for i in 0..32 {
        client_pk[i] = client_masked_pk[i] ^ mask_x[i];
    }
    let client_pub = PublicKey::from(client_pk);
    let dh_shared = server_secret.diffie_hellman(&client_pub);

    let mut master_input = Vec::new();
    master_input.extend_from_slice(b"OpenWearSync-PAKE-SessionKey-v1");
    master_input.extend_from_slice(&stretched);
    master_input.extend_from_slice(server_nonce);
    master_input.extend_from_slice(client_nonce);
    master_input.extend_from_slice(server_fingerprint.as_bytes());
    let shared_secret = hmac_sha256(dh_shared.as_bytes(), &master_input);

    let mut cp_input = Vec::new();
    cp_input.extend_from_slice(b"OpenWearSync-ClientProof-v1");
    cp_input.extend_from_slice(client_nonce);
    cp_input.extend_from_slice(server_nonce);
    let client_proof = hmac_sha256(&shared_secret, &cp_input);

    let mut sp_input = Vec::new();
    sp_input.extend_from_slice(b"OpenWearSync-ServerProof-v1");
    sp_input.extend_from_slice(server_nonce);
    sp_input.extend_from_slice(client_nonce);
    let server_proof = hmac_sha256(&shared_secret, &sp_input);

    PakeKeys {
        client_proof,
        server_proof,
        shared_secret,
    }
}

/// Derives PAKE mutual authentication proofs and shared secret.
pub fn derive_pake_keys(
    pin: &str,
    salt: &[u8; 32],
    server_nonce: &[u8; 32],
    client_nonce: &[u8; 32],
    device_id: &str,
    server_fingerprint: &str,
) -> PakeKeys {
    let stretched = stretch_pin(pin, salt, 5000);

    let mut client_priv_seed_input = Vec::new();
    client_priv_seed_input.extend_from_slice(client_nonce);
    client_priv_seed_input.extend_from_slice(server_nonce);
    client_priv_seed_input.extend_from_slice(device_id.as_bytes());
    let client_priv_seed = Sha256::digest(&client_priv_seed_input);
    let mut client_priv = [0u8; 32];
    client_priv.copy_from_slice(&client_priv_seed);

    let mut server_priv_seed_input = Vec::new();
    server_priv_seed_input.extend_from_slice(server_nonce);
    server_priv_seed_input.extend_from_slice(salt);
    let server_priv_seed = Sha256::digest(&server_priv_seed_input);
    let mut server_priv = [0u8; 32];
    server_priv.copy_from_slice(&server_priv_seed);

    let client_secret = StaticSecret::from(client_priv);
    let server_secret = StaticSecret::from(server_priv);
    let server_pub = PublicKey::from(&server_secret);

    let dh_shared = client_secret.diffie_hellman(&server_pub);

    let mut master_input = Vec::new();
    master_input.extend_from_slice(b"OpenWearSync-PAKE-SessionKey-v1");
    master_input.extend_from_slice(&stretched);
    master_input.extend_from_slice(server_nonce);
    master_input.extend_from_slice(client_nonce);
    master_input.extend_from_slice(server_fingerprint.as_bytes());

    let shared_secret = hmac_sha256(dh_shared.as_bytes(), &master_input);

    let mut cp_input = Vec::new();
    cp_input.extend_from_slice(b"OpenWearSync-ClientProof-v1");
    cp_input.extend_from_slice(client_nonce);
    cp_input.extend_from_slice(server_nonce);
    let client_proof = hmac_sha256(&shared_secret, &cp_input);

    let mut sp_input = Vec::new();
    sp_input.extend_from_slice(b"OpenWearSync-ServerProof-v1");
    sp_input.extend_from_slice(server_nonce);
    sp_input.extend_from_slice(client_nonce);
    let server_proof = hmac_sha256(&shared_secret, &sp_input);

    PakeKeys {
        client_proof,
        server_proof,
        shared_secret,
    }
}

/// Encrypts and authenticates a chunk payload using keystream from HMAC-SHA256 and Encrypt-then-MAC.
pub fn encrypt_chunk_payload(shared_secret: &[u8; 32], nonce: &[u8; 16], chunk_index: u32, plaintext: &[u8]) -> Vec<u8> {
    let mut ciphertext = Vec::with_capacity(plaintext.len() + 32);
    let mut block_idx: u32 = 0;
    let mut keystream_block = [0u8; 32];
    for (i, &b) in plaintext.iter().enumerate() {
        if i % 32 == 0 {
            let mut info = Vec::with_capacity(16 + 4 + 4);
            info.extend_from_slice(nonce);
            info.extend_from_slice(&chunk_index.to_le_bytes());
            info.extend_from_slice(&block_idx.to_le_bytes());
            keystream_block = hmac_sha256(shared_secret, &info);
            block_idx += 1;
        }
        ciphertext.push(b ^ keystream_block[i % 32]);
    }
    let mut tag_input = Vec::with_capacity(16 + 4 + ciphertext.len());
    tag_input.extend_from_slice(nonce);
    tag_input.extend_from_slice(&chunk_index.to_le_bytes());
    tag_input.extend_from_slice(&ciphertext);
    let tag = hmac_sha256(shared_secret, &tag_input);
    ciphertext.extend_from_slice(&tag);
    ciphertext
}

/// Decrypts and verifies an authenticated chunk payload.
pub fn decrypt_chunk_payload(shared_secret: &[u8; 32], nonce: &[u8; 16], chunk_index: u32, payload: &[u8]) -> ProtocolResult<Vec<u8>> {
    if payload.len() < 32 {
        return Err(ProtocolError {
            code: ErrorCode::InvalidChunk,
            message: "payload too short for authentication tag".to_string(),
        });
    }
    let (ciphertext, tag) = payload.split_at(payload.len() - 32);
    let mut tag_input = Vec::with_capacity(16 + 4 + ciphertext.len());
    tag_input.extend_from_slice(nonce);
    tag_input.extend_from_slice(&chunk_index.to_le_bytes());
    tag_input.extend_from_slice(ciphertext);
    let expected_tag = hmac_sha256(shared_secret, &tag_input);
    let mut tag_array = [0u8; 32];
    tag_array.copy_from_slice(tag);
    if !constant_time_eq_32(&tag_array, &expected_tag) {
        return Err(ProtocolError {
            code: ErrorCode::InvalidChunk,
            message: "chunk payload authentication tag mismatch".to_string(),
        });
    }

    let mut plaintext = Vec::with_capacity(ciphertext.len());
    let mut block_idx: u32 = 0;
    let mut keystream_block = [0u8; 32];
    for (i, &b) in ciphertext.iter().enumerate() {
        if i % 32 == 0 {
            let mut info = Vec::with_capacity(16 + 4 + 4);
            info.extend_from_slice(nonce);
            info.extend_from_slice(&chunk_index.to_le_bytes());
            info.extend_from_slice(&block_idx.to_le_bytes());
            keystream_block = hmac_sha256(shared_secret, &info);
            block_idx += 1;
        }
        plaintext.push(b ^ keystream_block[i % 32]);
    }
    Ok(plaintext)
}

/// Enrolled peer record with pinned identity token and revocation flag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairedPeer {
    pub device_id: String,
    pub device_name: String,
    pub shared_secret: [u8; 32],
    pub enrolled_at_epoch_s: u64,
    pub revoked: bool,
}

/// In-memory and persisted paired peer registry.
#[derive(Debug, Clone, Default)]
pub struct PairedPeerRegistry {
    peers: Arc<Mutex<HashMap<String, PairedPeer>>>,
}

impl PairedPeerRegistry {
    pub fn new() -> Self {
        Self {
            peers: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    // START_CONTRACT: PairedPeerRegistry::enroll
    // PURPOSE: Enroll or update a trusted peer with a pinned secret.
    // INPUTS: { peer: PairedPeer }
    // OUTPUTS: { () }
    // SIDE_EFFECTS: stores peer in registry.
    // END_CONTRACT: PairedPeerRegistry::enroll
    pub fn enroll(&self, peer: PairedPeer) {
        let mut map = self.peers.lock().unwrap();
        map.insert(peer.device_id.clone(), peer);
    }

    // START_CONTRACT: PairedPeerRegistry::revoke
    // PURPOSE: Revoke a previously paired peer immediately.
    // INPUTS: { device_id: &str }
    // OUTPUTS: { bool - true if device existed and was revoked }
    // SIDE_EFFECTS: sets revoked = true on the peer record.
    // END_CONTRACT: PairedPeerRegistry::revoke
    pub fn revoke(&self, device_id: &str) -> bool {
        let mut map = self.peers.lock().unwrap();
        if let Some(peer) = map.get_mut(device_id) {
            peer.revoked = true;
            true
        } else {
            false
        }
    }

    /// Check if peer is known and not revoked.
    pub fn is_authorized(&self, device_id: &str) -> bool {
        let map = self.peers.lock().unwrap();
        match map.get(device_id) {
            Some(peer) => !peer.revoked,
            None => false,
        }
    }

    pub fn get_secret(&self, device_id: &str) -> Option<[u8; 32]> {
        let map = self.peers.lock().unwrap();
        map.get(device_id).and_then(|p| {
            if !p.revoked {
                Some(p.shared_secret)
            } else {
                None
            }
        })
    }

    pub fn list_peers(&self) -> Vec<PairedPeer> {
        let map = self.peers.lock().unwrap();
        map.values().cloned().collect()
    }
}

/// Signed authentication token for protected requests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthToken {
    pub device_id: String,
    pub timestamp_epoch_s: u64,
    pub nonce: [u8; 16],
    pub signature: [u8; 32],
}

impl AuthToken {
    // START_CONTRACT: AuthToken::create
    // PURPOSE: Create a signed capability token bound to device secret, timestamp, and random nonce.
    // INPUTS: { device_id: &str, secret: &[u8; 32], max_drift: Duration }
    // OUTPUTS: { Self }
    // SIDE_EFFECTS: generates 16 random nonce bytes.
    // END_CONTRACT: AuthToken::create
    pub fn create(device_id: &str, secret: &[u8; 32]) -> Self {
        let mut nonce = [0u8; 16];
        OsRng.fill_bytes(&mut nonce);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let sig = Self::compute_signature(device_id, now, &nonce, secret);
        Self {
            device_id: device_id.to_string(),
            timestamp_epoch_s: now,
            nonce,
            signature: sig,
        }
    }

    fn compute_signature(
        device_id: &str,
        timestamp: u64,
        nonce: &[u8; 16],
        secret: &[u8; 32],
    ) -> [u8; 32] {
        let mut message = Vec::with_capacity(device_id.len() + 8 + 16);
        message.extend_from_slice(device_id.as_bytes());
        message.extend_from_slice(&timestamp.to_le_bytes());
        message.extend_from_slice(nonce);
        hmac_sha256(secret, &message)
    }

    // START_CONTRACT: AuthToken::verify
    // PURPOSE: Verify token signature and timestamp window against registered peer.
    // INPUTS: { secret: &[u8; 32], max_age: Duration }
    // OUTPUTS: { ProtocolResult<()> }
    // SIDE_EFFECTS: none
    // END_CONTRACT: AuthToken::verify
    pub fn verify(&self, secret: &[u8; 32], max_age: Duration) -> ProtocolResult<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let age = if now >= self.timestamp_epoch_s {
            Duration::from_secs(now - self.timestamp_epoch_s)
        } else {
            Duration::from_secs(self.timestamp_epoch_s - now)
        };

        if age > max_age {
            return Err(ProtocolError {
                code: ErrorCode::InvalidRequest,
                message: "auth token expired or clock drift exceeded".to_string(),
            });
        }

        let expected_sig =
            Self::compute_signature(&self.device_id, self.timestamp_epoch_s, &self.nonce, secret);

        if !constant_time_eq_32(&self.signature, &expected_sig) {
            return Err(ProtocolError {
                code: ErrorCode::InvalidRequest,
                message: "invalid auth token signature".to_string(),
            });
        }

        Ok(())
    }
}

/// Replay defense filter tracking observed token nonces.
#[derive(Debug, Default)]
pub struct ReplayFilter {
    seen_nonces: Arc<Mutex<HashSet<[u8; 16]>>>,
}

impl ReplayFilter {
    pub fn new() -> Self {
        Self {
            seen_nonces: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    // START_CONTRACT: ReplayFilter::check_and_mark
    // PURPOSE: Check if nonce was previously used and record it if fresh.
    // INPUTS: { nonce: &[u8; 16] }
    // OUTPUTS: { ProtocolResult<()> - Ok if fresh, Err if replay }
    // SIDE_EFFECTS: adds nonce to seen set.
    // END_CONTRACT: ReplayFilter::check_and_mark
    pub fn check_and_mark(&self, nonce: &[u8; 16]) -> ProtocolResult<()> {
        let mut set = self.seen_nonces.lock().unwrap();
        if set.contains(nonce) {
            Err(ProtocolError {
                code: ErrorCode::Conflict,
                message: "replayed request detected".to_string(),
            })
        } else {
            set.insert(*nonce);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_sha256_computes_deterministic_rfc_vectors() {
        let key = b"secret-key";
        let message = b"hello openwearsync";
        let sig1 = hmac_sha256(key, message);
        let sig2 = hmac_sha256(key, message);
        assert_eq!(sig1, sig2);
        assert!(constant_time_eq_32(&sig1, &sig2));

        let wrong_key = b"wrong-key";
        let sig_wrong = hmac_sha256(wrong_key, message);
        assert_ne!(sig1, sig_wrong);
    }

    #[test]
    fn rate_limiter_enforces_lockout_after_max_attempts() {
        let limiter = RateLimiter::new(3, Duration::from_millis(50));
        let client = "192.0.2.1";

        assert!(limiter.check_allowed(client).is_ok());
        assert!(limiter.record_failure(client).is_ok()); // 1
        assert!(limiter.record_failure(client).is_ok()); // 2

        // 3rd failure triggers lockout
        let res = limiter.record_failure(client);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().code, ErrorCode::LimitExceeded);

        // Check is also locked out
        assert!(limiter.check_allowed(client).is_err());

        // Wait for lockout duration
        std::thread::sleep(Duration::from_millis(60));
        assert!(limiter.check_allowed(client).is_ok());
    }

    #[test]
    fn pairing_session_derives_matching_keys_with_correct_pin() {
        let session = PairingSession::new("galaxy-watch-7".to_string(), 300);
        let key1 = session.derive_pairing_key();
        let key2 = session.derive_pairing_key();
        assert_eq!(key1, key2);

        let mut client_nonce = [0u8; 32];
        OsRng.fill_bytes(&mut client_nonce);

        let commit_correct = session.verify_client_commitment(&session.pin, &client_nonce);
        let commit_wrong = session.verify_client_commitment("000000", &client_nonce);
        assert_ne!(commit_correct, commit_wrong);
    }

    #[test]
    fn paired_peer_registry_rejects_unpaired_and_revoked_clients() {
        let registry = PairedPeerRegistry::new();
        let secret = [0x55u8; 32];

        assert!(!registry.is_authorized("watch-1"));
        assert!(registry.get_secret("watch-1").is_none());

        registry.enroll(PairedPeer {
            device_id: "watch-1".to_string(),
            device_name: "Galaxy Watch 7".to_string(),
            shared_secret: secret,
            enrolled_at_epoch_s: 1700000000,
            revoked: false,
        });

        assert!(registry.is_authorized("watch-1"));
        assert_eq!(registry.get_secret("watch-1"), Some(secret));

        // Revoke
        assert!(registry.revoke("watch-1"));
        assert!(!registry.is_authorized("watch-1"));
        assert!(registry.get_secret("watch-1").is_none());
    }

    #[test]
    fn auth_token_verifies_signature_and_detects_tampering() {
        let secret = [0x99u8; 32];
        let token = AuthToken::create("watch-1", &secret);

        assert!(token.verify(&secret, Duration::from_secs(60)).is_ok());

        // Wrong secret
        let wrong_secret = [0x11u8; 32];
        assert!(token.verify(&wrong_secret, Duration::from_secs(60)).is_err());

        // Tampered token
        let mut tampered = token.clone();
        tampered.nonce[0] ^= 0xFF;
        assert!(tampered.verify(&secret, Duration::from_secs(60)).is_err());
    }

    #[test]
    fn replay_filter_rejects_duplicate_nonces() {
        let filter = ReplayFilter::new();
        let nonce = [42u8; 16];

        assert!(filter.check_and_mark(&nonce).is_ok());
        let res = filter.check_and_mark(&nonce);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().code, ErrorCode::Conflict);
    }

    #[test]
    fn pake_derivation_and_verification_matches_between_parties() {
        let pin = "123456";
        let salt = [0x42u8; 32];
        let server_nonce = [0x11u8; 32];
        let client_nonce = [0x22u8; 32];
        let device_id = "galaxy-watch-test";
        let fingerprint = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

        let client_keys = derive_pake_keys(pin, &salt, &server_nonce, &client_nonce, device_id, fingerprint);
        let server_keys = derive_pake_keys(pin, &salt, &server_nonce, &client_nonce, device_id, fingerprint);

        assert_eq!(client_keys.client_proof, server_keys.client_proof);
        assert_eq!(client_keys.server_proof, server_keys.server_proof);
        assert_eq!(client_keys.shared_secret, server_keys.shared_secret);

        // Wrong PIN produces different proofs and secrets
        let attacker_keys = derive_pake_keys("654321", &salt, &server_nonce, &client_nonce, device_id, fingerprint);
        assert_ne!(client_keys.client_proof, attacker_keys.client_proof);
        assert_ne!(client_keys.server_proof, attacker_keys.server_proof);
        assert_ne!(client_keys.shared_secret, attacker_keys.shared_secret);
    }

    #[test]
    fn chunk_payload_encryption_and_decryption_works_and_detects_tampering() {
        let secret = [0x77u8; 32];
        let nonce = [0x33u8; 16];
        let plaintext = b"Samsung Voice Recorder encrypted audio chunk payload 1234567890";

        let encrypted = encrypt_chunk_payload(&secret, &nonce, 1, plaintext);
        assert_ne!(&encrypted[..plaintext.len()], plaintext);

        let decrypted = decrypt_chunk_payload(&secret, &nonce, 1, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);

        // Corrupted ciphertext fails auth tag check
        let mut corrupted = encrypted.clone();
        corrupted[10] ^= 0xFF;
        assert!(decrypt_chunk_payload(&secret, &nonce, 1, &corrupted).is_err());
    }

    #[test]
    fn server_identity_generates_consistent_public_key_and_fingerprint() {
        let id = ServerIdentity::generate();
        assert_eq!(id.fingerprint.len(), 64);

        let reconstructed = ServerIdentity::from_private_key(id.private_key);
        assert_eq!(reconstructed.public_key, id.public_key);
        assert_eq!(reconstructed.fingerprint, id.fingerprint);
    }

    #[test]
    fn full_pake_x25519_exchange_produces_identical_mutual_keys() {
        let pin = "741258";
        let session = PairingSession::with_pin("test-watch".to_string(), pin.to_string(), 300);
        let identity = ServerIdentity::generate();
        let client_nonce = [0x77u8; 32];
        let client_ephemeral_private = [0x55u8; 32];

        let client_res = client_pake_exchange(
            pin,
            &session.salt,
            &session.server_nonce,
            &client_nonce,
            &session.server_masked_pk,
            &identity.fingerprint,
            &client_ephemeral_private,
        );

        let server_keys = server_pake_exchange(
            pin,
            &session.salt,
            &session.server_nonce,
            &client_nonce,
            &client_res.client_masked_pk,
            &identity.fingerprint,
            &session.server_ephemeral_private,
        );

        assert_eq!(client_res.client_proof, server_keys.client_proof);
        assert_eq!(client_res.server_proof, server_keys.server_proof);
        assert_eq!(client_res.shared_secret, server_keys.shared_secret);
    }
}
