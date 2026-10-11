//! Android ARM64 Rust JNI bridge and safe lifecycle/cancellation interface.

use openwearsync_protocol::{ErrorCode, ProtocolError};
use openwearsync_transfer_core::{CancellationToken, TransferReconciliation};
use std::sync::{
    atomic::{AtomicI32, AtomicU64, Ordering},
    Mutex,
};

// START_MODULE_CONTRACT
// PURPOSE: Android ARM64 Rust JNI bridge and safe lifecycle/cancellation interface.
// SCOPE: Handle-based session lifecycle, FFI boundaries, cancellation signalling, error mapping.
// DEPENDS: openwearsync-protocol, openwearsync-security, openwearsync-transfer-core, serde, serde_json
// LINKS: M-ANDROID-PLATFORM, M-TRANSFER-CORE, V-M-ANDROID-PLATFORM, DF-ENCRYPTED-CHUNK-UPLOAD, DF-LIFECYCLE-CLEANUP
// END_MODULE_CONTRACT

// START_MODULE_MAP
//   NativeSessionState - enum representing the lifecycle of an active native transfer session.
//   NativeSessionHandle - heap-allocated thread-safe state container returned to Java as a 64-bit pointer.
//   map_error_to_code - maps Rust errors to deterministic integer error codes for Java.
//   native_create_session - FFI constructor for transfer session handle.
//   native_cancel_session - FFI canceller setting cancellation token.
//   native_get_progress - FFI reader for transferred bytes and total bytes.
//   native_destroy_session - FFI destructor safely deallocating handle.
// END_MODULE_MAP

/// Integer error codes exposed across JNI to Kotlin.
pub const ERROR_OK: i32 = 0;
pub const ERROR_INVALID_ARGUMENT: i32 = -1;
pub const ERROR_CANCELLED: i32 = -2;
pub const ERROR_NETWORK_FAILED: i32 = -3;
pub const ERROR_CHECKSUM_MISMATCH: i32 = -4;
pub const ERROR_UNPAIRED: i32 = -5;
pub const ERROR_UNKNOWN: i32 = -99;

pub fn map_error_to_code(err: &ProtocolError) -> i32 {
    match err.code {
        ErrorCode::InvalidFrame | ErrorCode::InvalidRequest | ErrorCode::InvalidManifest | ErrorCode::InvalidChunk => {
            ERROR_INVALID_ARGUMENT
        }
        ErrorCode::Conflict => ERROR_CANCELLED,
        ErrorCode::TransferNotFound => ERROR_NETWORK_FAILED,
        ErrorCode::LimitExceeded => ERROR_NETWORK_FAILED,
        ErrorCode::UnsupportedVersion => ERROR_INVALID_ARGUMENT,
        ErrorCode::AlreadyCommitted => ERROR_OK,
    }
}

/// Lifecycle states of a native session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum SessionStatus {
    Idle = 0,
    Active = 1,
    Completed = 2,
    Cancelled = 3,
    Failed = 4,
}

/// Opaque thread-safe session container held behind a raw pointer in Java.
pub struct NativeSessionHandle {
    pub token: CancellationToken,
    pub status: AtomicI32,
    pub transferred_bytes: AtomicU64,
    pub total_bytes: AtomicU64,
    pub last_error_code: AtomicI32,
    pub reconciliation: Mutex<TransferReconciliation>,
}

impl NativeSessionHandle {
    pub fn new(total_bytes: u64) -> Self {
        Self {
            token: CancellationToken::new(),
            status: AtomicI32::new(SessionStatus::Active as i32),
            transferred_bytes: AtomicU64::new(0),
            total_bytes: AtomicU64::new(total_bytes),
            last_error_code: AtomicI32::new(ERROR_OK),
            reconciliation: Mutex::new(TransferReconciliation::new(total_bytes)),
        }
    }

    pub fn cancel(&self) {
        self.token.cancel();
        self.status.store(SessionStatus::Cancelled as i32, Ordering::SeqCst);
    }

    pub fn pause(&self) {
        self.status.store(SessionStatus::Idle as i32, Ordering::SeqCst);
    }

    pub fn resume(&self) {
        self.status.store(SessionStatus::Active as i32, Ordering::SeqCst);
    }

    pub fn set_progress(&self, transferred: u64) {
        self.transferred_bytes.store(transferred, Ordering::SeqCst);
    }

    pub fn record_chunk(&self, offset: u64, length: u32) {
        let mut rec = self.reconciliation.lock().unwrap();
        rec.record_chunk(offset, length);
        self.transferred_bytes.store(rec.received_bytes(), Ordering::SeqCst);
        if rec.is_complete() {
            self.status.store(SessionStatus::Completed as i32, Ordering::SeqCst);
        }
    }

    pub fn is_chunk_received(&self, offset: u64, length: u32) -> bool {
        let rec = self.reconciliation.lock().unwrap();
        rec.is_chunk_received(offset, length)
    }

    pub fn mark_completed(&self) {
        self.status.store(SessionStatus::Completed as i32, Ordering::SeqCst);
    }

    pub fn mark_failed(&self, code: i32) {
        self.last_error_code.store(code, Ordering::SeqCst);
        self.status.store(SessionStatus::Failed as i32, Ordering::SeqCst);
    }
}

// START_CONTRACT: native_create_session
// PURPOSE: Allocate a new native session handle on the heap and return its pointer.
// INPUTS: { total_bytes: u64 }
// OUTPUTS: { *mut NativeSessionHandle - raw pointer, never null }
// SIDE_EFFECTS: heap allocation via Box::into_raw.
// END_CONTRACT: native_create_session
#[no_mangle]
pub extern "C" fn native_create_session(total_bytes: u64) -> *mut NativeSessionHandle {
    let handle = Box::new(NativeSessionHandle::new(total_bytes));
    Box::into_raw(handle)
}

// START_CONTRACT: native_cancel_session
// PURPOSE: Signal cooperative cancellation on the session handle.
// INPUTS: { handle: *mut NativeSessionHandle }
// OUTPUTS: { i32 - ERROR_OK on success or ERROR_INVALID_ARGUMENT if null }
// SIDE_EFFECTS: sets cancellation token atomic flag.
// END_CONTRACT: native_cancel_session
#[no_mangle]
pub extern "C" fn native_cancel_session(handle: *mut NativeSessionHandle) -> i32 {
    if handle.is_null() {
        return ERROR_INVALID_ARGUMENT;
    }
    unsafe {
        (*handle).cancel();
    }
    ERROR_OK
}

#[no_mangle]
pub extern "C" fn native_pause_session(handle: *mut NativeSessionHandle) -> i32 {
    if handle.is_null() {
        return ERROR_INVALID_ARGUMENT;
    }
    unsafe {
        (*handle).pause();
    }
    ERROR_OK
}

#[no_mangle]
pub extern "C" fn native_resume_session(handle: *mut NativeSessionHandle) -> i32 {
    if handle.is_null() {
        return ERROR_INVALID_ARGUMENT;
    }
    unsafe {
        (*handle).resume();
    }
    ERROR_OK
}

// START_CONTRACT: native_get_status
// PURPOSE: Query the current lifecycle status of a session handle.
// INPUTS: { handle: *const NativeSessionHandle }
// OUTPUTS: { i32 - SessionStatus value or -1 if null }
// SIDE_EFFECTS: none
// END_CONTRACT: native_get_status
#[no_mangle]
pub extern "C" fn native_get_status(handle: *const NativeSessionHandle) -> i32 {
    if handle.is_null() {
        return -1;
    }
    unsafe { (*handle).status.load(Ordering::SeqCst) }
}

// START_CONTRACT: native_get_progress
// PURPOSE: Read transferred bytes from session handle.
// INPUTS: { handle: *const NativeSessionHandle }
// OUTPUTS: { u64 - transferred bytes or 0 if null }
// SIDE_EFFECTS: none
// END_CONTRACT: native_get_progress
#[no_mangle]
pub extern "C" fn native_get_progress(handle: *const NativeSessionHandle) -> u64 {
    if handle.is_null() {
        return 0;
    }
    unsafe { (*handle).transferred_bytes.load(Ordering::SeqCst) }
}

#[no_mangle]
pub extern "C" fn native_record_chunk(
    handle: *mut NativeSessionHandle,
    offset: u64,
    length: u32,
) -> i32 {
    if handle.is_null() {
        return ERROR_INVALID_ARGUMENT;
    }
    unsafe {
        (*handle).record_chunk(offset, length);
    }
    ERROR_OK
}

#[no_mangle]
pub extern "C" fn native_is_chunk_received(
    handle: *const NativeSessionHandle,
    offset: u64,
    length: u32,
) -> i32 {
    if handle.is_null() {
        return 0;
    }
    if unsafe { (*handle).is_chunk_received(offset, length) } {
        1
    } else {
        0
    }
}

// START_CONTRACT: native_destroy_session
// PURPOSE: Free the heap-allocated session handle.
// INPUTS: { handle: *mut NativeSessionHandle }
// OUTPUTS: { i32 - ERROR_OK or ERROR_INVALID_ARGUMENT }
// SIDE_EFFECTS: deallocates session memory via Box::from_raw.
// END_CONTRACT: native_destroy_session
#[no_mangle]
pub extern "C" fn native_destroy_session(handle: *mut NativeSessionHandle) -> i32 {
    if handle.is_null() {
        return ERROR_INVALID_ARGUMENT;
    }
    unsafe {
        drop(Box::from_raw(handle));
    }
    ERROR_OK
}

// Pinned HTTPS socket transport executed in Rust.
use std::io::{BufRead, BufReader, Read, Write};
use std::time::Duration;

pub fn execute_https_request(
    host: &str,
    port: u16,
    certificate_pin: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
    timeout: Duration,
) -> Result<(u16, Vec<u8>), i32> {
    let mut stream = openwearsync_security::tls::connect_pinned(host, port, certificate_pin, timeout)
        .map_err(|_| ERROR_NETWORK_FAILED)?;

    let mut req = format!(
        "{} {} HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\nContent-Length: {}\r\n",
        method, path, host, port, body.len()
    );
    for (k, v) in headers {
        req.push_str(&format!("{}: {}\r\n", k, v));
    }
    req.push_str("\r\n");

    stream.write_all(req.as_bytes()).map_err(|_| ERROR_NETWORK_FAILED)?;
    if !body.is_empty() {
        stream.write_all(body).map_err(|_| ERROR_NETWORK_FAILED)?;
    }
    stream.flush().map_err(|_| ERROR_NETWORK_FAILED)?;

    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    (&mut reader).take(8193).read_line(&mut status_line).map_err(|_| ERROR_NETWORK_FAILED)?;
    if status_line.len() > 8192 { return Err(ERROR_NETWORK_FAILED); }
    let parts: Vec<&str> = status_line.split_whitespace().collect();
    let status_code = parts.get(1).and_then(|c| c.parse::<u16>().ok()).unwrap_or(0);

    let mut content_length = 0usize;
    let mut header_count = 0;
    loop {
        let mut line = String::new();
        if (&mut reader).take(8193).read_line(&mut line).map_err(|_| ERROR_NETWORK_FAILED)? == 0 {
            break;
        }
        header_count += 1;
        if line.len() > 8192 || header_count > 64 { return Err(ERROR_NETWORK_FAILED); }
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

    if content_length > openwearsync_protocol::MAX_FRAME_BYTES as usize { return Err(ERROR_NETWORK_FAILED); }
    let mut resp_body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut resp_body).map_err(|_| ERROR_NETWORK_FAILED)?;
    } else {
        return Err(ERROR_NETWORK_FAILED);
    }

    Ok((status_code, resp_body))
}

// Minimal JNIEnv interface table matching Android ART & HotSpot ABI
#[derive(Copy, Clone)]
#[repr(C)]
pub struct JniEnvTable {
    _prefix: [*const (); 169],
    pub get_string_utf_chars: extern "C" fn(*mut JniEnv, *mut (), *mut u8) -> *const std::ffi::c_char,
    pub release_string_utf_chars: extern "C" fn(*mut JniEnv, *mut (), *const std::ffi::c_char),
    pub get_array_length: extern "C" fn(*mut JniEnv, *mut ()) -> i32,
    _pad_arr: [*const (); 12],
    pub get_byte_array_elements: extern "C" fn(*mut JniEnv, *mut (), *mut u8) -> *mut i8,
    _pad_arr2: [*const (); 7],
    pub release_byte_array_elements: extern "C" fn(*mut JniEnv, *mut (), *mut i8, i32),
    _pad_arr3: [*const (); 15],
    pub set_byte_array_region: extern "C" fn(*mut JniEnv, *mut (), i32, i32, *const i8),
}

pub type JniEnv = *const JniEnvTable;

unsafe fn jbyte_array_to_vec(env: *mut JniEnv, jarr: *mut ()) -> Option<Vec<u8>> {
    if jarr.is_null() || env.is_null() { return None; }
    let table = **env;
    let len = (table.get_array_length)(env, jarr) as usize;
    let ptr = (table.get_byte_array_elements)(env, jarr, std::ptr::null_mut());
    if ptr.is_null() { return None; }
    let slice = std::slice::from_raw_parts(ptr as *const u8, len);
    let vec = slice.to_vec();
    (table.release_byte_array_elements)(env, jarr, ptr, 0);
    Some(vec)
}

unsafe fn copy_slice_to_jbyte_array(env: *mut JniEnv, jarr: *mut (), slice: &[u8]) {
    if jarr.is_null() || env.is_null() { return; }
    let table = **env;
    (table.set_byte_array_region)(env, jarr, 0, slice.len() as i32, slice.as_ptr() as *const i8);
}

// Crypto & security helpers
#[no_mangle]
pub extern "C" fn native_compute_sha256(
    data_ptr: *const u8,
    data_len: usize,
    out_sha_ptr: *mut u8,
) -> i32 {
    if data_ptr.is_null() || out_sha_ptr.is_null() {
        return ERROR_INVALID_ARGUMENT;
    }
    let data = unsafe { std::slice::from_raw_parts(data_ptr, data_len) };
    let hash = openwearsync_transfer_core::hash_sha256(data);
    unsafe {
        std::ptr::copy_nonoverlapping(hash.as_ptr(), out_sha_ptr, 32);
    }
    ERROR_OK
}

// JNI bindings for com.openwearsync.wear.NativeTransferBridge
#[no_mangle]
pub unsafe extern "C" fn Java_com_openwearsync_wear_NativeTransferBridge_nativeCreateSession(
    _env: *mut std::ffi::c_void,
    _class: *mut std::ffi::c_void,
    total_bytes: i64,
) -> i64 {
    native_create_session(total_bytes as u64) as i64
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_openwearsync_wear_NativeTransferBridge_nativeCancelSession(
    _env: *mut std::ffi::c_void,
    _class: *mut std::ffi::c_void,
    handle: i64,
) -> i32 {
    native_cancel_session(handle as *mut NativeSessionHandle)
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_openwearsync_wear_NativeTransferBridge_nativePauseSession(
    _env: *mut std::ffi::c_void,
    _class: *mut std::ffi::c_void,
    handle: i64,
) -> i32 {
    native_pause_session(handle as *mut NativeSessionHandle)
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_openwearsync_wear_NativeTransferBridge_nativeResumeSession(
    _env: *mut std::ffi::c_void,
    _class: *mut std::ffi::c_void,
    handle: i64,
) -> i32 {
    native_resume_session(handle as *mut NativeSessionHandle)
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_openwearsync_wear_NativeTransferBridge_nativeGetStatus(
    _env: *mut std::ffi::c_void,
    _class: *mut std::ffi::c_void,
    handle: i64,
) -> i32 {
    native_get_status(handle as *const NativeSessionHandle)
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_openwearsync_wear_NativeTransferBridge_nativeGetProgress(
    _env: *mut std::ffi::c_void,
    _class: *mut std::ffi::c_void,
    handle: i64,
) -> i64 {
    native_get_progress(handle as *const NativeSessionHandle) as i64
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_openwearsync_wear_NativeTransferBridge_nativeRecordChunk(
    _env: *mut std::ffi::c_void,
    _class: *mut std::ffi::c_void,
    handle: i64,
    offset: i64,
    length: i32,
) -> i32 {
    native_record_chunk(handle as *mut NativeSessionHandle, offset as u64, length as u32)
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_openwearsync_wear_NativeTransferBridge_nativeIsChunkReceived(
    _env: *mut std::ffi::c_void,
    _class: *mut std::ffi::c_void,
    handle: i64,
    offset: i64,
    length: i32,
) -> i32 {
    native_is_chunk_received(handle as *const NativeSessionHandle, offset as u64, length as u32)
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_openwearsync_wear_NativeTransferBridge_nativeDestroySession(
    _env: *mut std::ffi::c_void,
    _class: *mut std::ffi::c_void,
    handle: i64,
) -> i32 {
    native_destroy_session(handle as *mut NativeSessionHandle)
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_openwearsync_wear_NativeTransferBridge_nativeHttpsRequest(
    mut env: jni::JNIEnv, _class: jni::objects::JClass,
    host: jni::objects::JString, port: jni::sys::jint, pin: jni::objects::JString,
    method: jni::objects::JString, path: jni::objects::JString, token: jni::objects::JString,
    sha: jni::objects::JString, encrypted: jni::sys::jint, body: jni::objects::JByteArray,
) -> jni::sys::jstring {
    let result = (|| -> Result<String, i32> {
        let host: String = env.get_string(&host).map_err(|_| ERROR_INVALID_ARGUMENT)?.into();
        let pin: String = env.get_string(&pin).map_err(|_| ERROR_INVALID_ARGUMENT)?.into();
        let method: String = env.get_string(&method).map_err(|_| ERROR_INVALID_ARGUMENT)?.into();
        let path: String = env.get_string(&path).map_err(|_| ERROR_INVALID_ARGUMENT)?.into();
        let token: String = env.get_string(&token).map_err(|_| ERROR_INVALID_ARGUMENT)?.into();
        let sha: String = env.get_string(&sha).map_err(|_| ERROR_INVALID_ARGUMENT)?.into();
        let body = env.convert_byte_array(&body).map_err(|_| ERROR_INVALID_ARGUMENT)?;
        if !(1..=65535).contains(&port) || !["GET", "POST", "PUT", "DELETE"].contains(&method.as_str()) ||
            !path.starts_with("/v1/") || path.bytes().any(|b| b.is_ascii_whitespace()) ||
            token.contains(['\r', '\n']) || (!sha.is_empty() && openwearsync_security::hex_to_32(&sha).is_none()) ||
            body.len() > openwearsync_protocol::MAX_FRAME_BYTES as usize { return Err(ERROR_INVALID_ARGUMENT); }
        let mut headers = vec![("Content-Type", if encrypted != 0 { "application/octet-stream" } else { "application/json" })];
        if !token.is_empty() { headers.push(("Authorization", token.as_str())); }
        if !sha.is_empty() { headers.push(("x-chunk-sha256", sha.as_str())); }
        if encrypted != 0 { headers.push(("x-encrypted", "true")); }
        let (status, response) = execute_https_request(&host, port as u16, &pin, &method, &path, &headers, &body, Duration::from_secs(10))?;
        Ok(format!("{}\n{}", status, String::from_utf8(response).map_err(|_| ERROR_NETWORK_FAILED)?))
    })();
    let response = result.unwrap_or_else(|e| format!("{}\nNative request failed", e));
    env.new_string(response).map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_openwearsync_wear_NativeTransferBridge_nativeEncryptChunk(
    env: *mut JniEnv,
    _class: *mut (),
    secret_jarr: *mut (),
    nonce_jarr: *mut (),
    chunk_index: i32,
    plaintext_jarr: *mut (),
    out_encrypted_jarr: *mut (),
) -> i32 {
    let secret_vec = match jbyte_array_to_vec(env, secret_jarr) { Some(v) if v.len() == 32 => v, _ => return ERROR_INVALID_ARGUMENT };
    let nonce_vec = match jbyte_array_to_vec(env, nonce_jarr) { Some(v) if v.len() == 16 => v, _ => return ERROR_INVALID_ARGUMENT };
    let plaintext = match jbyte_array_to_vec(env, plaintext_jarr) { Some(v) => v, None => return ERROR_INVALID_ARGUMENT };

    let mut secret = [0u8; 32];
    secret.copy_from_slice(&secret_vec);
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&nonce_vec);

    let encrypted = openwearsync_security::encrypt_chunk_payload(&secret, &nonce, chunk_index as u32, &plaintext);
    copy_slice_to_jbyte_array(env, out_encrypted_jarr, &encrypted);
    encrypted.len() as i32
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_openwearsync_wear_NativeTransferBridge_nativeComputeSha256(
    env: *mut JniEnv,
    _class: *mut (),
    data_jarr: *mut (),
    out_sha_jarr: *mut (),
) -> i32 {
    let data = match jbyte_array_to_vec(env, data_jarr) { Some(v) => v, None => return ERROR_INVALID_ARGUMENT };
    let hash = openwearsync_transfer_core::hash_sha256(&data);
    copy_slice_to_jbyte_array(env, out_sha_jarr, &hash);
    ERROR_OK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_lifecycle_creates_cancels_updates_and_destroys_safely() {
        let handle = native_create_session(5000);
        assert!(!handle.is_null());

        assert_eq!(native_get_status(handle), SessionStatus::Active as i32);
        assert_eq!(native_get_progress(handle), 0);

        unsafe {
            (*handle).set_progress(2500);
        }
        assert_eq!(native_get_progress(handle), 2500);

        assert_eq!(native_cancel_session(handle), ERROR_OK);
        assert_eq!(native_get_status(handle), SessionStatus::Cancelled as i32);

        assert_eq!(native_destroy_session(handle), ERROR_OK);
    }

    #[test]
    fn null_handle_calls_return_safe_error_codes_without_crashing() {
        assert_eq!(native_cancel_session(std::ptr::null_mut()), ERROR_INVALID_ARGUMENT);
        assert_eq!(native_get_status(std::ptr::null()), -1);
        assert_eq!(native_get_progress(std::ptr::null()), 0);
        assert_eq!(native_destroy_session(std::ptr::null_mut()), ERROR_INVALID_ARGUMENT);
    }

    #[test]
    fn error_mapping_translates_protocol_errors_to_jvm_codes() {
        let err_invalid = ProtocolError {
            code: ErrorCode::InvalidRequest,
            message: "bad".to_string(),
        };
        assert_eq!(map_error_to_code(&err_invalid), ERROR_INVALID_ARGUMENT);

        let err_cancel = ProtocolError {
            code: ErrorCode::Conflict,
            message: "stop".to_string(),
        };
        assert_eq!(map_error_to_code(&err_cancel), ERROR_CANCELLED);
    }

    #[test]
    fn reconciliation_and_crypto_operations_work_via_ffi() {
        let handle = native_create_session(100_000);
        assert_eq!(native_is_chunk_received(handle, 0, 50_000), 0);

        assert_eq!(native_record_chunk(handle, 0, 50_000), ERROR_OK);
        assert_eq!(native_is_chunk_received(handle, 0, 50_000), 1);
        assert_eq!(native_get_progress(handle), 50_000);
        assert_eq!(native_get_status(handle), SessionStatus::Active as i32);

        assert_eq!(native_pause_session(handle), ERROR_OK);
        assert_eq!(native_get_status(handle), SessionStatus::Idle as i32);
        assert_eq!(native_resume_session(handle), ERROR_OK);
        assert_eq!(native_get_status(handle), SessionStatus::Active as i32);

        assert_eq!(native_record_chunk(handle, 50_000, 50_000), ERROR_OK);
        assert_eq!(native_get_progress(handle), 100_000);
        assert_eq!(native_get_status(handle), SessionStatus::Completed as i32);

        // Test native SHA-256
        let data = b"hello openwearsync";
        let mut sha = [0u8; 32];
        assert_eq!(native_compute_sha256(data.as_ptr(), data.len(), sha.as_mut_ptr()), ERROR_OK);
        assert_eq!(sha, openwearsync_transfer_core::hash_sha256(data));

        assert_eq!(native_destroy_session(handle), ERROR_OK);
    }
}
