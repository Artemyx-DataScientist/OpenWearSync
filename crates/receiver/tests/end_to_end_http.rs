// START_MODULE_CONTRACT
// PURPOSE: Real pinned TLS socket integration test for OpenWearSync receiver service.
// SCOPE: Verification of real network listener, PIN pairing, auth tokens, chunk streaming, reconciliation, and commit.
// DEPENDS: openwearsync-protocol, openwearsync-security, openwearsync-transfer-core, openwearsync-receiver
// LINKS: M-WINDOWS-RECEIVER, M-PAIRING-SECURITY, V-M-WINDOWS-RECEIVER, DF-RECORDING-MANIFEST, DF-ENCRYPTED-CHUNK-UPLOAD
// END_MODULE_CONTRACT
//
// START_MODULE_MAP
//   end_to_end_real_https_socket_transfer - integration test executing complete HTTP workflow over real TCP.
// END_MODULE_MAP

use openwearsync_protocol::Manifest;
use openwearsync_receiver::{DurableFileStore, DurableTransferLedger, HttpServer, ReceiverService};
use openwearsync_security::{AuthToken, PairedPeerRegistry};
use openwearsync_transfer_core::hash_sha256;
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::SocketAddr,
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


fn send_pinned_https(
    addr: SocketAddr,
    certificate_pin: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> (u16, Vec<u8>) {
    let mut stream = openwearsync_security::tls::connect_pinned(&addr.ip().to_string(), addr.port(), certificate_pin, Duration::from_secs(5)).expect("Authenticated TLS connection failed");

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
fn end_to_end_real_https_socket_transfer() {
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
    let (status, body) = send_pinned_https(addr, &service.server_fingerprint(), "GET", "/v1/status", &[], b"");
    assert_eq!(status, 200);
    assert!(String::from_utf8_lossy(&body).contains("protocol"));

    // 2. Initiate pairing session on receiver
    let session_body = br#"{"pin":"741258","ttl_secs":300}"#;
    let (status, resp) = send_pinned_https(addr, &service.server_fingerprint(), "POST", "/v1/pair/session", &[("Content-Type", "application/json")], session_body);
    assert_eq!(status, 201);
    assert!(String::from_utf8_lossy(&resp).contains("741258"));

    // Enrollment PIN is sent only within the independently authenticated TLS channel.
    let wrong = br#"{"device_id":"watch-http-test","device_name":"Watch","pin":"000000"}"#;
    assert_eq!(send_pinned_https(addr, &service.server_fingerprint(), "POST", "/v1/pair/enroll", &[], wrong).0, 401);
    let enroll = br#"{"device_id":"watch-http-test","device_name":"Watch","pin":"741258"}"#;
    let (code, response) = send_pinned_https(addr, &service.server_fingerprint(), "POST", "/v1/pair/enroll", &[], enroll);
    assert_eq!(code, 200);
    let enrolled: serde_json::Value = serde_json::from_slice(&response).unwrap();
    let shared_secret = openwearsync_security::hex_to_32(enrolled["shared_secret_hex"].as_str().unwrap()).unwrap();
    assert_eq!(send_pinned_https(addr, &service.server_fingerprint(), "POST", "/v1/pair/enroll", &[], enroll).0, 401);
    // 4b. Test reconcile on non-existent transfer -> must return 404 TransferNotFound!
    let non_existent_token = AuthToken::create("watch-http-test", &shared_secret);
    let non_existent_auth = format!("Bearer {}", serde_json::to_string(&non_existent_token).unwrap());
    let (reconcile_404_status, _) = send_pinned_https(addr, &service.server_fingerprint(),
        "POST",
        "/v1/transfers/tx-does-not-exist/reconcile",
        &[("Authorization", &non_existent_auth)],
        b"{}",
    );
    assert_eq!(reconcile_404_status, 404, "Reconciling non-existent transfer must return 404!");

    // 5. Verify /v1/peers DOES NOT expose shared_secret
    let (status, peers_resp) = send_pinned_https(addr, &service.server_fingerprint(), "GET", "/v1/peers", &[], b"");
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

    let (status, _) = send_pinned_https(addr, &service.server_fingerprint(), "POST", "/v1/transfers", &[("Content-Type", "application/json")], &manifest_json);
    assert_eq!(status, 400, "Unauthenticated create transfer must be rejected");

    // 7. Create transfer WITH valid AuthToken
    let auth_token = AuthToken::create("watch-http-test", &shared_secret);
    let auth_json = serde_json::to_string(&auth_token).unwrap();
    let auth_header = format!("Bearer {}", auth_json);

    let (status, create_resp) = send_pinned_https(addr, &service.server_fingerprint(),
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
    let (status, chunk0_resp) = send_pinned_https(addr, &service.server_fingerprint(),
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
    let (status, rec_resp) = send_pinned_https(addr, &service.server_fingerprint(),
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
    let (status, chunk1_resp) = send_pinned_https(addr, &service.server_fingerprint(),
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
    let (status, commit_resp) = send_pinned_https(addr, &service.server_fingerprint(),
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

