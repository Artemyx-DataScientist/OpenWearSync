//! Windows receiver TLS network listener and HTTPS protocol dispatcher.

use crate::ReceiverService;
use openwearsync_protocol::{
    ChunkDescriptor, CommitRequest, CreateTransferRequest, ErrorCode, ProtocolError,
    ReconcileRequest, Request, StatusRequest, UploadChunkRequest, MAX_FRAME_BYTES,
};
use openwearsync_security::{AuthToken, tls::{TlsStream, ServerConnection}};
type Connection = BufReader<TlsStream<ServerConnection, TcpStream>>;
use std::{
    collections::HashMap,
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

// START_MODULE_CONTRACT
// PURPOSE: Windows receiver network listener and HTTP/1.1 protocol dispatcher.
// SCOPE: TLS-only listening, bounded connections and HTTP framing, authentication extraction, REST route dispatch, and shutdown.
// DEPENDS: openwearsync-protocol, openwearsync-security, openwearsync-receiver
// LINKS: M-WINDOWS-RECEIVER, V-M-WINDOWS-RECEIVER, DF-ENCRYPTED-CHUNK-UPLOAD, DF-RECORDING-MANIFEST
// END_MODULE_CONTRACT

// START_MODULE_MAP
//   HttpServer - standalone TCP/HTTP network listener routing requests to ReceiverService.
//   ServerHandle - control handle for stopping a running background server.
// END_MODULE_MAP

/// Control handle for a background receiver server.
pub struct ServerHandle {
    running: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    addr: SocketAddr,
}

impl ServerHandle {
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn stop(mut self) {
        self.running.store(false, Ordering::SeqCst);
        // Poke listener to unblock accept if needed
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(50));
        if let Some(th) = self.thread.take() {
            let _ = th.join();
        }
    }
}

/// Standalone HTTP receiver server bound to local LAN interface.
pub struct HttpServer {
    listener: TcpListener,
    service: Arc<ReceiverService>,
    connections: Arc<AtomicUsize>,
}

struct ConnectionLease(Arc<AtomicUsize>);
impl Drop for ConnectionLease {
    fn drop(&mut self) { self.0.fetch_sub(1, Ordering::AcqRel); }
}
fn spawn_connection(stream: TcpStream, service: Arc<ReceiverService>, connections: &Arc<AtomicUsize>) {
    // Bound unauthenticated TLS handshakes as well as established application requests.
    if connections.fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| (n < 32).then_some(n + 1)).is_err() {
        return;
    }
    let lease = ConnectionLease(connections.clone());
    let _ = thread::Builder::new().name("ows-https".into()).spawn(move || {
        let _lease = lease;
        let _ = handle_connection(stream, &service);
    });
}

impl HttpServer {
    // START_CONTRACT: HttpServer::bind
    // PURPOSE: Bind receiver TCP listener to requested host and port.
    // INPUTS: { addr: &str, service: Arc<ReceiverService> }
    // OUTPUTS: { std::io::Result<Self> }
    // SIDE_EFFECTS: binds OS TCP socket.
    // END_CONTRACT: HttpServer::bind
    pub fn bind(addr: &str, service: Arc<ReceiverService>) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        listener.set_nonblocking(false)?;
        Ok(Self { listener, service, connections: Arc::new(AtomicUsize::new(0)) })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Spawns the server loop in a background thread and returns a shutdown handle.
    pub fn start_background(self) -> std::io::Result<ServerHandle> {
        let addr = self.local_addr()?;
        let running = Arc::new(AtomicBool::new(true));
        let running_clone = running.clone();

        // Set short timeout so the loop checks running flag
        self.listener.set_nonblocking(false)?;

        let thread = thread::spawn(move || {
            let _ = self.listener.set_nonblocking(false);
            while running_clone.load(Ordering::SeqCst) {
                match self.listener.accept() {
                    Ok((stream, _)) => {
                        if !running_clone.load(Ordering::SeqCst) {
                            break;
                        }
                        spawn_connection(stream, self.service.clone(), &self.connections);
                    }
                    Err(_) => {
                        thread::sleep(Duration::from_millis(10));
                    }
                }
            }
        });

        Ok(ServerHandle {
            running,
            thread: Some(thread),
            addr,
        })
    }

    /// Run the server synchronously on the current thread.
    pub fn run(&self) -> std::io::Result<()> {
        for stream in self.listener.incoming() {
            match stream {
                Ok(stream) => {
                    spawn_connection(stream, self.service.clone(), &self.connections);
                }
                Err(e) => {
                    eprintln!("accept error: {}", e);
                }
            }
        }
        Ok(())
    }
}

/// Helper parsing hex bytes
fn parse_hex_32(s: &str) -> Option<[u8; 32]> {
    openwearsync_security::hex_to_32(s)
}

fn parse_hex_16(s: &str) -> Option<[u8; 16]> {
    openwearsync_security::hex_to_16(s)
}

fn extract_auth_token(headers: &HashMap<String, String>) -> Option<AuthToken> {
    // 1. Try JSON in Authorization header: "Bearer {...}"
    if let Some(auth_val) = headers.get("authorization") {
        let trimmed = auth_val.trim();
        if let Some(json_str) = trimmed.strip_prefix("Bearer ") {
            if let Ok(token) = serde_json::from_str::<AuthToken>(json_str.trim()) {
                return Some(token);
            }
        }
    }

    // 2. Try explicit headers
    let device_id = headers.get("x-device-id")?.clone();
    let timestamp = headers.get("x-timestamp")?.parse::<u64>().ok()?;
    let nonce_str = headers.get("x-nonce")?;
    let nonce = parse_hex_16(nonce_str)?;
    let sig_str = headers.get("x-signature")?;
    let signature = parse_hex_32(sig_str)?;

    Some(AuthToken {
        device_id,
        timestamp_epoch_s: timestamp,
        nonce,
        signature,
    })
}

fn send_response(mut stream: Connection, status_code: u16, status_text: &str, body: &[u8], content_type: &str) {
    let response_headers = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status_code,
        status_text,
        content_type,
        body.len()
    );
    let _ = stream.get_mut().write_all(response_headers.as_bytes());
    let _ = stream.get_mut().write_all(body);
    let _ = stream.get_mut().flush();
}

fn send_error(stream: Connection, error: ProtocolError) {
    let status_code = match error.code {
        ErrorCode::InvalidRequest | ErrorCode::InvalidFrame | ErrorCode::InvalidManifest | ErrorCode::InvalidChunk => 400,
        ErrorCode::TransferNotFound => 404,
        ErrorCode::Conflict | ErrorCode::AlreadyCommitted => 409,
        ErrorCode::LimitExceeded => 429,
        _ => 500,
    };
    let json = serde_json::to_vec(&error).unwrap_or_else(|_| b"{\"message\":\"internal error\"}".to_vec());
    send_response(stream, status_code, "Error", &json, "application/json");
}

fn handle_connection(stream: TcpStream, service: &ReceiverService) -> std::io::Result<()> {
    let is_loopback = stream.peer_addr().map(|a| a.ip().is_loopback()).unwrap_or(false);
    stream.set_read_timeout(Some(Duration::from_secs(15)))?;
    stream.set_write_timeout(Some(Duration::from_secs(15)))?;

    let tls = ServerConnection::new(service.tls_config()).map_err(std::io::Error::other)?;
    let mut stream = BufReader::new(TlsStream::new(tls, stream));

    // Read request line
    let mut request_line = String::new();
    if (&mut stream).take(8193).read_line(&mut request_line)? == 0 {
        return Ok(());
    }

    let parts: Vec<&str> = request_line.trim().split_whitespace().collect();
    if parts.len() < 2 || request_line.len() > 8192 {
        send_response(stream, 400, "Bad Request", b"Malformed request line", "text/plain");
        return Ok(());
    }

    let method = parts[0];
    let path = parts[1];

    // Read headers
    let mut headers = HashMap::new();
    let mut header_count = 0;
    loop {
        let mut header_line = String::new();
        if (&mut stream).take(8193).read_line(&mut header_line)? == 0 {
            break;
        }
        header_count += 1;
        if header_line.len() > 8192 || header_count > 64 {
            send_response(stream, 400, "Bad Request", b"Headers exceed bounds", "text/plain");
            return Ok(());
        }
        let trimmed = header_line.trim();
        if trimmed.is_empty() {
            break;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            headers.insert(k.trim().to_lowercase(), v.trim().to_string());
        }
    }

    let content_length = headers
        .get("content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);

    if content_length > MAX_FRAME_BYTES as usize {
        send_response(stream, 413, "Payload Too Large", b"Frame exceeds maximum allowed size", "text/plain");
        return Ok(());
    }

    // Read body
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        stream.read_exact(&mut body)?;
    }

    // Routing
    if method == "GET" && path == "/v1/status" {
        let req = StatusRequest {
            client_name: headers.get("x-client-name").cloned().unwrap_or_else(|| "openwearsync-client".to_string()),
        };
        match service.handle_request(Request::Status(req), None) {
            Ok(resp) => {
                let mut val = serde_json::to_value(&resp).unwrap_or_default();
                if let serde_json::Value::Object(ref mut map) = val {
                    map.insert(
                        "server_fingerprint".to_string(),
                        serde_json::Value::String(service.server_fingerprint()),
                    );
                }
                let json = serde_json::to_vec(&val).unwrap();
                send_response(stream, 200, "OK", &json, "application/json");
            }
            Err(e) => send_error(stream, e),
        }
        return Ok(());
    }

    if method == "POST" && path == "/v1/pair/session" {
        if !is_loopback {
            send_response(
                stream,
                403,
                "Forbidden",
                b"{\"error\":\"pairing session can only be initiated from localhost\"}",
                "application/json",
            );
            return Ok(());
        }

        #[derive(serde::Deserialize)]
        struct CreateSessionReq {
            pin: Option<String>,
            ttl_secs: Option<u64>,
        }
        #[derive(serde::Serialize)]
        struct SessionResp {
            session_id: String,
            pin: String,
            expires_at_epoch_s: u64,
        }

        let req_opt: Option<CreateSessionReq> = serde_json::from_slice(&body).ok();
        let ttl = req_opt.as_ref().and_then(|r| r.ttl_secs).unwrap_or(300).clamp(1, 300);
        if let Some(pin) = req_opt.as_ref().and_then(|r| r.pin.as_ref()) {
            if pin.len() != 6 || !pin.bytes().all(|b| b.is_ascii_digit()) {
                send_response(stream, 400, "Bad Request", b"PIN must have six digits", "text/plain"); return Ok(());
            }
        }
        let session = if let Some(pin) = req_opt.as_ref().and_then(|r| r.pin.as_ref()) {
            service.set_pairing_pin(pin, ttl)
        } else {
            service.start_pairing_session(None, ttl)
        };

        let resp = SessionResp {
            session_id: session.session_id,
            pin: session.pin,
            expires_at_epoch_s: session.expires_at_epoch_s,
        };
        let json = serde_json::to_vec(&resp).unwrap();
        send_response(stream, 201, "Created", &json, "application/json");
        return Ok(());
    }

    if method == "POST" && path == "/v1/pair/enroll" {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Enroll { device_id: String, device_name: String, pin: String }
        let enrollment: Enroll = match serde_json::from_slice(&body) {
            Ok(e) => e,
            Err(_) => { send_response(stream, 400, "Bad Request", b"Invalid enrollment", "text/plain"); return Ok(()); }
        };
        if enrollment.device_id.is_empty() || enrollment.device_id.len() > 128 ||
            !enrollment.device_id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') ||
            enrollment.device_name.len() > 128 || enrollment.pin.len() != 6 || !enrollment.pin.bytes().all(|b| b.is_ascii_digit()) {
            send_response(stream, 400, "Bad Request", b"Invalid enrollment fields", "text/plain"); return Ok(());
        }
        match service.enroll_with_pin(&enrollment.device_id, &enrollment.device_name, &enrollment.pin) {
            Ok(peer) => {
                let response = serde_json::json!({"status":"paired", "credential_version":2,
                    "shared_secret_hex":openwearsync_security::bytes_to_hex(&peer.shared_secret), "server_fingerprint":service.server_fingerprint()});
                send_response(stream, 200, "OK", &serde_json::to_vec(&response).unwrap(), "application/json");
            }
            Err(_) => send_response(stream, 401, "Unauthorized", b"Invalid, consumed, expired or locked pairing session", "text/plain"),
        }
        return Ok(());
    }

    if method == "GET" && path == "/v1/peers" {
        if !is_loopback { send_response(stream, 403, "Forbidden", b"Local administration only", "text/plain"); return Ok(()); }
        #[derive(serde::Serialize)]
        struct SafePeerDto {
            device_id: String,
            device_name: String,
            enrolled_at_epoch_s: u64,
            revoked: bool,
        }

        let peers: Vec<SafePeerDto> = service
            .registry()
            .list_peers()
            .into_iter()
            .map(|p| SafePeerDto {
                device_id: p.device_id,
                device_name: p.device_name,
                enrolled_at_epoch_s: p.enrolled_at_epoch_s,
                revoked: p.revoked,
            })
            .collect();
        let json = serde_json::to_vec(&peers).unwrap_or_default();
        send_response(stream, 200, "OK", &json, "application/json");
        return Ok(());
    }

    if method == "DELETE" && path.starts_with("/v1/peers/") {
        if !is_loopback {
            send_response(
                stream,
                403,
                "Forbidden",
                b"{\"error\":\"peer revocation can only be performed from localhost\"}",
                "application/json",
            );
            return Ok(());
        }
        let device_id = &path["/v1/peers/".len()..];
        let revoked = service.revoke_peer(device_id);
        let resp = serde_json::json!({ "device_id": device_id, "revoked": revoked });
        let json = serde_json::to_vec(&resp).unwrap();
        send_response(stream, 200, "OK", &json, "application/json");
        return Ok(());
    }

    if method == "GET" && path == "/v1/transfers" {
        if !is_loopback { send_response(stream, 403, "Forbidden", b"Local administration only", "text/plain"); return Ok(()); }
        let transfers = service.store().ledger().list_transfers();
        let json = serde_json::to_vec(&transfers).unwrap_or_default();
        send_response(stream, 200, "OK", &json, "application/json");
        return Ok(());
    }

    let token = extract_auth_token(&headers);

    if method == "POST" && path == "/v1/transfers" {
        let manifest = match serde_json::from_slice::<CreateTransferRequest>(&body) {
            Ok(req) => req.manifest,
            Err(_) => match serde_json::from_slice::<openwearsync_protocol::Manifest>(&body) {
                Ok(m) => m,
                Err(e) => {
                    send_error(stream, ProtocolError {
                        code: ErrorCode::InvalidRequest,
                        message: format!("cannot parse transfer manifest: {}", e),
                    });
                    return Ok(());
                }
            },
        };

        match service.handle_request(Request::CreateTransfer(CreateTransferRequest { manifest }), token.as_ref()) {
            Ok(resp) => {
                let json = serde_json::to_vec(&resp).unwrap();
                send_response(stream, 201, "Created", &json, "application/json");
            }
            Err(e) => send_error(stream, e),
        }
        return Ok(());
    }

    // Pattern: /v1/transfers/{id}/reconcile
    if method == "POST" && path.starts_with("/v1/transfers/") && path.ends_with("/reconcile") {
        let trimmed = &path["/v1/transfers/".len()..];
        let transfer_id = trimmed.trim_end_matches("/reconcile").to_string();

        match service.handle_request(Request::ReconcileTransfer(ReconcileRequest { transfer_id }), token.as_ref()) {
            Ok(resp) => {
                let json = serde_json::to_vec(&resp).unwrap();
                send_response(stream, 200, "OK", &json, "application/json");
            }
            Err(e) => send_error(stream, e),
        }
        return Ok(());
    }

    // Pattern: /v1/transfers/{id}/chunks/{offset}
    if method == "PUT" && path.starts_with("/v1/transfers/") && path.contains("/chunks/") {
        let sub = &path["/v1/transfers/".len()..];
        if let Some((transfer_id, offset_str)) = sub.split_once("/chunks/") {
            let offset = match offset_str.parse::<u64>() {
                Ok(off) => off,
                Err(_) => {
                    send_error(stream, ProtocolError {
                        code: ErrorCode::InvalidChunk,
                        message: "invalid chunk offset in path".to_string(),
                    });
                    return Ok(());
                }
            };

            let is_encrypted = headers.get("x-encrypted").map(|v| v == "true").unwrap_or(false);
            let final_body = if is_encrypted {
                let token_ref = match token.as_ref() {
                    Some(t) => t,
                    None => {
                        send_error(stream, ProtocolError {
                            code: ErrorCode::InvalidRequest,
                            message: "encrypted chunk requires authentication token".to_string(),
                        });
                        return Ok(());
                    }
                };
                let secret = match service.registry().get_secret(&token_ref.device_id) {
                    Some(s) => s,
                    None => {
                        send_error(stream, ProtocolError {
                            code: ErrorCode::InvalidRequest,
                            message: "device secret not found for chunk decryption".to_string(),
                        });
                        return Ok(());
                    }
                };
                let chunk_idx = (offset / 65536) as u32;
                match openwearsync_security::decrypt_chunk_payload(&secret, &token_ref.nonce, chunk_idx, &body) {
                    Ok(dec) => dec,
                    Err(e) => {
                        send_error(stream, e);
                        return Ok(());
                    }
                }
            } else {
                body
            };

            let sha_opt = headers.get("x-chunk-sha256").and_then(|s| parse_hex_32(s));
            let chunk_sha = match sha_opt {
                Some(s) => s,
                None => { send_response(stream, 400, "Bad Request", b"Plaintext SHA-256 is required", "text/plain"); return Ok(()); },
            };

            let chunk_desc = match ChunkDescriptor::new(offset, final_body.len() as u32, chunk_sha) {
                Ok(c) => c,
                Err(e) => {
                    send_error(stream, e);
                    return Ok(());
                }
            };

            let req = UploadChunkRequest {
                transfer_id: transfer_id.to_string(),
                chunk: chunk_desc,
                payload: final_body,
            };

            match service.handle_request(Request::UploadChunk(req), token.as_ref()) {
                Ok(resp) => {
                    let json = serde_json::to_vec(&resp).unwrap();
                    send_response(stream, 200, "OK", &json, "application/json");
                }
                Err(e) => send_error(stream, e),
            }
            return Ok(());
        }
    }

    // Pattern: /v1/transfers/{id}/commit
    if method == "POST" && path.starts_with("/v1/transfers/") && path.ends_with("/commit") {
        let trimmed = &path["/v1/transfers/".len()..];
        let transfer_id = trimmed.trim_end_matches("/commit").to_string();

        match service.handle_request(Request::CommitTransfer(CommitRequest { transfer_id }), token.as_ref()) {
            Ok(resp) => {
                let json = serde_json::to_vec(&resp).unwrap();
                send_response(stream, 200, "OK", &json, "application/json");
            }
            Err(e) => send_error(stream, e),
        }
        return Ok(());
    }

    send_response(stream, 404, "Not Found", b"Endpoint not found", "text/plain");
    Ok(())
}
