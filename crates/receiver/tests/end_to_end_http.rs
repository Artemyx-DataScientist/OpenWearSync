// START_MODULE_CONTRACT
// PURPOSE: Real TCP HTTP socket integration test for OpenWearSync receiver service.
// SCOPE: Verification of real network listener, PIN pairing, auth tokens, chunk streaming, reconciliation, and commit.
// DEPENDS: openwearsync-protocol, openwearsync-security, openwearsync-transfer-core, openwearsync-receiver
// LINKS: M-WINDOWS-RECEIVER, M-PAIRING-SECURITY, V-M-WINDOWS-RECEIVER, DF-RECORDING-MANIFEST, DF-ENCRYPTED-CHUNK-UPLOAD
// END_MODULE_CONTRACT
//
// START_MODULE_MAP
//   end_to_end_real_http_socket_transfer - integration test executing complete HTTP workflow over real TCP.
// END_MODULE_MAP

use openwearsync_protocol::Manifest;
use openwearsync_receiver::{DurableFileStore, DurableTransferLedger, HttpServer, ReceiverService};
use openwearsync_security::{AuthToken, PairedPeerRegistry};
use openwearsync_transfer_core::hash_sha256;
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpStream},
    sync::Arc,
    time::Duration,
};
use tempfile::tempdir;

fn to_hex_str(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}


fn send_raw_http(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> (u16, Vec<u8>) {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).expect("connect failed");
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();

    let mut req = format!("{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Length: {}\r\n", method, path, addr, body.len());
    for (k, v) in headers {
        req.push_str(&format!("{}: {}\r\n", k, v));
    }
    req.push_str("\r\n");

    stream.write_all(req.as_bytes()).unwrap();
    if !body.is_empty() {
        stream.write_all(body).unwrap();
    }
    stream.flush().unwrap();

    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader.read_line(&mut status_line).unwrap();
    let parts: Vec<&str> = status_line.split_whitespace().collect();
    let status_code = parts.get(1).and_then(|c| c.parse::<u16>().ok()).unwrap_or(0);

    // Read headers until blank line
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap() == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                content_length = v.trim().parse().unwrap_or(0);
            }
        }
    }

    let mut resp_body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut resp_body).unwrap();
    } else {
        let _ = reader.read_to_end(&mut resp_body);
    }

    (status_code, resp_body)
}

#[test]
fn end_to_end_real_http_socket_transfer() {
    let temp = tempdir().unwrap();
    let ledger_path = temp.path().join("ledger.db");
    let staging_dir = temp.path().join("staging");
    let dest_dir = temp.path().join("recordings");

    let ledger = DurableTransferLedger::open(&ledger_path).unwrap();
    let store = Arc::new(DurableFileStore::new(staging_dir, dest_dir.clone(), ledger).unwrap());
    let registry = Arc::new(PairedPeerRegistry::new());
    let service = Arc::new(ReceiverService::new(store, registry, 4));

    // Bind real TCP server on ephemeral port
    let server = HttpServer::bind("127.0.0.1:0", service.clone()).unwrap();
    let handle = server.start_background().unwrap();
    let addr = handle.local_addr();

    // 1. Health check status
    let (status, body) = send_raw_http(addr, "GET", "/v1/status", &[], b"");
    assert_eq!(status, 200);
    assert!(String::from_utf8_lossy(&body).contains("protocol"));

    // 2. Initiate pairing session on receiver
    let session_body = br#"{"pin":"741258","ttl_secs":300}"#;
    let (status, resp) = send_raw_http(addr, "POST", "/v1/pair/session", &[("Content-Type", "application/json")], session_body);
    assert_eq!(status, 201);
    assert!(String::from_utf8_lossy(&resp).contains("741258"));

    // 3. Attempt pairing with WRONG PIN -> must be rejected with 401
    let wrong_pair_body = br#"{"device_id":"watch-http-test","device_name":"Galaxy Watch Ultra","pin":"000000"}"#;
    let (status, _) = send_raw_http(addr, "POST", "/v1/pair", &[("Content-Type", "application/json")], wrong_pair_body);
    assert_eq!(status, 401, "Wrong PIN must be rejected with 401");

    // 4. Pair with CORRECT PIN -> must succeed with 200
    let correct_pair_body = br#"{"device_id":"watch-http-test","device_name":"Galaxy Watch Ultra","pin":"741258"}"#;
    let (status, resp) = send_raw_http(addr, "POST", "/v1/pair", &[("Content-Type", "application/json")], correct_pair_body);
    assert_eq!(status, 200, "Correct PIN must succeed with 200");
    let resp_str = String::from_utf8_lossy(&resp);
    assert!(resp_str.contains("paired"));

    // Verify server_fingerprint is present and shared_secret_hex is NOT leaked
    let json_val: serde_json::Value = serde_json::from_slice(&resp).unwrap();
    assert!(json_val.get("server_fingerprint").is_some());
    assert!(json_val.get("shared_secret_hex").is_none(), "Server must NOT leak shared secret over the wire!");

    // Client derives shared secret locally from PIN and device ID
    let shared_secret = openwearsync_security::hmac_sha256(b"741258", b"watch-http-test");

    // 4b. Test reconcile on non-existent transfer -> must return 404 TransferNotFound!
    let non_existent_token = AuthToken::create("watch-http-test", &shared_secret);
    let non_existent_auth = format!("Bearer {}", serde_json::to_string(&non_existent_token).unwrap());
    let (reconcile_404_status, _) = send_raw_http(
        addr,
        "POST",
        "/v1/transfers/tx-does-not-exist/reconcile",
        &[("Authorization", &non_existent_auth)],
        b"{}",
    );
    assert_eq!(reconcile_404_status, 404, "Reconciling non-existent transfer must return 404!");

    // 5. Verify /v1/peers DOES NOT expose shared_secret
    let (status, peers_resp) = send_raw_http(addr, "GET", "/v1/peers", &[], b"");
    assert_eq!(status, 200);
    let peers_str = String::from_utf8_lossy(&peers_resp);
    assert!(peers_str.contains("watch-http-test"));
    assert!(!peers_str.contains("shared_secret"), "GET /v1/peers must NEVER leak shared_secret!");

    // 6. Test that unauthenticated transfer creation is rejected
    let payload = vec![0xABu8; 128 * 1024]; // 128 KB audio file
    let audio_sha = hash_sha256(&payload);
    let manifest = Manifest::new(
        "tx-http-test-1".to_string(),
        "Voice_Recording_Test.m4a".to_string(),
        payload.len() as u64,
        audio_sha,
        1700000000,
    ).unwrap();
    let manifest_json = serde_json::to_vec(&manifest).unwrap();

    let (status, _) = send_raw_http(addr, "POST", "/v1/transfers", &[("Content-Type", "application/json")], &manifest_json);
    assert_eq!(status, 400, "Unauthenticated create transfer must be rejected");

    // 7. Create transfer WITH valid AuthToken
    let auth_token = AuthToken::create("watch-http-test", &shared_secret);
    let auth_json = serde_json::to_string(&auth_token).unwrap();
    let auth_header = format!("Bearer {}", auth_json);

    let (status, create_resp) = send_raw_http(
        addr,
        "POST",
        "/v1/transfers",
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &auth_header),
        ],
        &manifest_json,
    );
    assert_eq!(status, 201, "Authenticated create transfer must succeed: {}", String::from_utf8_lossy(&create_resp));

    // 8. Upload Chunk 0 (first 64 KB) with fresh AuthToken
    let chunk0 = &payload[..64 * 1024];
    let chunk0_sha_hex = to_hex_str(&hash_sha256(chunk0));
    let chunk0_path = "/v1/transfers/tx-http-test-1/chunks/0";
    let chunk0_token = AuthToken::create("watch-http-test", &shared_secret);
    let chunk0_auth = format!("Bearer {}", serde_json::to_string(&chunk0_token).unwrap());
    let (status, chunk0_resp) = send_raw_http(
        addr,
        "PUT",
        chunk0_path,
        &[
            ("Content-Type", "application/octet-stream"),
            ("Authorization", &chunk0_auth),
            ("x-chunk-sha256", &chunk0_sha_hex),
        ],
        chunk0,
    );
    assert_eq!(status, 200, "Chunk 0 upload must succeed: {}", String::from_utf8_lossy(&chunk0_resp));

    // 9. Reconcile transfer over HTTP to test resume capability
    let fresh_token1 = AuthToken::create("watch-http-test", &shared_secret);
    let fresh_auth1 = format!("Bearer {}", serde_json::to_string(&fresh_token1).unwrap());
    let (status, rec_resp) = send_raw_http(
        addr,
        "POST",
        "/v1/transfers/tx-http-test-1/reconcile",
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &fresh_auth1),
        ],
        b"{}",
    );
    assert_eq!(status, 200);
    let rec_val: serde_json::Value = serde_json::from_slice(&rec_resp).unwrap();
    assert_eq!(rec_val["result"], "reconciled");
    assert_eq!(rec_val["transfer_id"], "tx-http-test-1");
    let received = rec_val["received"].as_array().unwrap();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0]["offset"], 0);
    assert_eq!(received[0]["length"], 65536);

    // 10. Upload Chunk 1 (second 64 KB) with authenticated encryption
    let chunk1 = &payload[64 * 1024..];
    let chunk1_sha_hex = to_hex_str(&hash_sha256(chunk1));
    let chunk1_path = "/v1/transfers/tx-http-test-1/chunks/65536";
    let fresh_token2 = AuthToken::create("watch-http-test", &shared_secret);
    let fresh_auth2 = format!("Bearer {}", serde_json::to_string(&fresh_token2).unwrap());
    let encrypted_chunk1 = openwearsync_security::encrypt_chunk_payload(&shared_secret, &fresh_token2.nonce, 1, chunk1);
    let (status, chunk1_resp) = send_raw_http(
        addr,
        "PUT",
        chunk1_path,
        &[
            ("Content-Type", "application/octet-stream"),
            ("Authorization", &fresh_auth2),
            ("x-encrypted", "true"),
            ("x-chunk-sha256", &chunk1_sha_hex),
        ],
        &encrypted_chunk1,
    );
    assert_eq!(status, 200, "Encrypted chunk 1 upload must succeed: {}", String::from_utf8_lossy(&chunk1_resp));

    // 11. Commit transfer over HTTP
    let fresh_token3 = AuthToken::create("watch-http-test", &shared_secret);
    let fresh_auth3 = format!("Bearer {}", serde_json::to_string(&fresh_token3).unwrap());
    let (status, commit_resp) = send_raw_http(
        addr,
        "POST",
        "/v1/transfers/tx-http-test-1/commit",
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &fresh_auth3),
        ],
        b"{}",
    );
    assert_eq!(status, 200, "Commit transfer must succeed: {}", String::from_utf8_lossy(&commit_resp));

    // 12. Verify file on disk and SQLite ledger state
    let final_path = dest_dir.join("Voice_Recording_Test.m4a");
    assert!(final_path.exists(), "Final file must be published on disk");
    let written_bytes = fs::read(&final_path).unwrap();
    assert_eq!(written_bytes.len(), 128 * 1024);
    assert_eq!(hash_sha256(&written_bytes), audio_sha);
    assert!(service.store().ledger().is_committed("tx-http-test-1"));

    // 13. Graceful shutdown
    handle.stop();
}

#[test]
fn end_to_end_pake_zero_knowledge_pairing_and_key_pinning() {
    let temp = tempdir().unwrap();
    let ledger_path = temp.path().join("ledger_pake.db");
    let staging_dir = temp.path().join("staging_pake");
    let dest_dir = temp.path().join("recordings_pake");

    let ledger = DurableTransferLedger::open(&ledger_path).unwrap();
    let store = Arc::new(DurableFileStore::new(staging_dir, dest_dir, ledger).unwrap());
    let registry = Arc::new(PairedPeerRegistry::new());
    let service = Arc::new(ReceiverService::new(store, registry, 2));

    let server = HttpServer::bind("127.0.0.1:0", service.clone()).unwrap();
    let handle = server.start_background().unwrap();
    let addr = handle.local_addr();

    // 1. Windows side initiates pairing session with a 6-digit PIN
    let session_body = br#"{"pin":"852963","ttl_secs":300}"#;
    let (status, sess_resp) = send_raw_http(addr, "POST", "/v1/pair/session", &[("Content-Type", "application/json")], session_body);
    assert_eq!(status, 201);
    let sess_val: serde_json::Value = serde_json::from_slice(&sess_resp).unwrap();
    let session_id = sess_val["session_id"].as_str().unwrap();

    // 2. Watch initiates PAKE pairing without sending PIN
    let client_nonce = [0x55u8; 32];
    let client_nonce_hex = to_hex_str(&client_nonce);
    let init_req = serde_json::json!({
        "device_id": "watch-pake-test",
        "client_nonce_hex": client_nonce_hex,
    });
    let (status, init_resp) = send_raw_http(addr, "POST", "/v1/pair/initiate", &[("Content-Type", "application/json")], &serde_json::to_vec(&init_req).unwrap());
    assert_eq!(status, 200);
    let init_val: serde_json::Value = serde_json::from_slice(&init_resp).unwrap();
    let server_nonce_hex = init_val["server_nonce_hex"].as_str().unwrap();
    let salt_hex = init_val["salt_hex"].as_str().unwrap();
    let server_fingerprint = init_val["server_fingerprint"].as_str().unwrap();

    let server_nonce = openwearsync_security::hex_to_32(server_nonce_hex).unwrap();
    let salt = openwearsync_security::hex_to_32(salt_hex).unwrap();

    // 3. Watch derives PAKE keys locally from entered PIN
    let pake_keys = openwearsync_security::derive_pake_keys(
        "852963",
        &salt,
        &server_nonce,
        &client_nonce,
        "watch-pake-test",
        server_fingerprint,
    );

    // 4. Watch sends confirm with client_proof (NO PIN ON WIRE!)
    let confirm_req = serde_json::json!({
        "session_id": session_id,
        "device_id": "watch-pake-test",
        "device_name": "Galaxy Watch 7 PAKE",
        "client_nonce_hex": client_nonce_hex,
        "client_proof_hex": to_hex_str(&pake_keys.client_proof),
    });
    let (status, confirm_resp) = send_raw_http(addr, "POST", "/v1/pair/confirm", &[("Content-Type", "application/json")], &serde_json::to_vec(&confirm_req).unwrap());
    assert_eq!(status, 200);
    let conf_val: serde_json::Value = serde_json::from_slice(&confirm_resp).unwrap();
    assert_eq!(conf_val["status"], "paired");

    // Verify server proof matches locally expected proof
    let server_proof_hex = conf_val["server_proof_hex"].as_str().unwrap();
    let server_proof = openwearsync_security::hex_to_32(server_proof_hex).unwrap();
    assert_eq!(server_proof, pake_keys.server_proof, "Server must prove possession of PIN!");

    // Verify peer is enrolled and can authenticate
    assert!(service.registry().is_authorized("watch-pake-test"));

    handle.stop();
}
