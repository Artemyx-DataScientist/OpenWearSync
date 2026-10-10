//! Android ARM64 Rust JNI bridge and safe lifecycle/cancellation interface.

use openwearsync_protocol::{ErrorCode, ProtocolError};
use openwearsync_transfer_core::CancellationToken;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};

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
}

impl NativeSessionHandle {
    pub fn new(total_bytes: u64) -> Self {
        Self {
            token: CancellationToken::new(),
            status: AtomicI32::new(SessionStatus::Active as i32),
            transferred_bytes: AtomicU64::new(0),
            total_bytes: AtomicU64::new(total_bytes),
            last_error_code: AtomicI32::new(ERROR_OK),
        }
    }

    pub fn cancel(&self) {
        self.token.cancel();
        self.status.store(SessionStatus::Cancelled as i32, Ordering::SeqCst);
    }

    pub fn set_progress(&self, transferred: u64) {
        self.transferred_bytes.store(transferred, Ordering::SeqCst);
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
}
