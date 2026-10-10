//! Versioned, bounded JSON wire contracts shared by the watch and receiver.
//!
//! Endpoint mapping:
//! * `Request::Status` / `Response::Status` — `GET /v1/status`
//! * `Request::CreateTransfer` / `Response::TransferCreated` — `POST /v1/transfers`
//! * `Request::ReconcileTransfer` / `Response::Reconciled` — `POST /v1/transfers/{id}/reconcile`
//! * `Request::UploadChunk` / `Response::ChunkAccepted` — idempotent `PUT /v1/transfers/{id}/chunks/{offset}`
//! * `Request::CommitTransfer` / `Response::Committed` — `POST /v1/transfers/{id}/commit`

use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt};

// START_MODULE_CONTRACT
// PURPOSE: Define the versioned and bounded OpenWearSync wire protocol.
// SCOPE: Typed manifests, capabilities, requests/responses, chunk descriptors, negotiation, and wire validation.
// DEPENDS: serde, serde_json.
// LINKS: M-TRANSFER-CORE, M-WINDOWS-RECEIVER, V-M-TRANSFER-CORE.
// END_MODULE_CONTRACT

// START_MODULE_MAP
// ProtocolVersion / Hello - negotiate a compatible protocol and peer limits.
// Manifest / ChunkDescriptor - describe durable source and chunk state.
// Request / Response - typed endpoint operations and results.
// encode_* / decode_* - deterministic bounded wire serialization.
// END_MODULE_MAP

pub const PROTOCOL_MAJOR: u16 = 1;
pub const PROTOCOL_MINOR: u16 = 0;
pub const MAX_FRAME_BYTES: u32 = 128 * 1024;
pub const MAX_CHUNK_BYTES: u32 = 64 * 1024;
pub const MAX_SUPPORTED_VERSIONS: usize = 8;
pub const MAX_METADATA_ENTRIES: usize = 32;
pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_FILENAME_BYTES: usize = 255;
pub const MAX_ERROR_MESSAGE_BYTES: usize = 256;
pub const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidFrame,
    InvalidRequest,
    InvalidManifest,
    InvalidChunk,
    LimitExceeded,
    UnsupportedVersion,
    TransferNotFound,
    Conflict,
    AlreadyCommitted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolError {
    pub code: ErrorCode,
    pub message: String,
}

impl ProtocolError {
    fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        let mut message = message.into();
        if message.len() > MAX_ERROR_MESSAGE_BYTES {
            message.truncate(MAX_ERROR_MESSAGE_BYTES);
        }
        Self { code, message }
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for ProtocolError {}
pub type ProtocolResult<T> = Result<T, ProtocolError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

impl ProtocolVersion {
    pub const CURRENT: Self = Self {
        major: PROTOCOL_MAJOR,
        minor: PROTOCOL_MINOR,
    };
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    pub max_frame_bytes: u32,
    pub max_chunk_bytes: u32,
    pub supports_reconcile: bool,
    pub supports_idempotent_chunks: bool,
}

impl Capabilities {
    // START_CONTRACT: Capabilities::new
    // PURPOSE: Construct limits that cannot exceed this implementation's hard bounds.
    // INPUTS: { max_frame_bytes: u32, max_chunk_bytes: u32 }
    // OUTPUTS: { ProtocolResult<Capabilities> - validated peer limits }
    // SIDE_EFFECTS: none
    // END_CONTRACT: Capabilities::new
    pub fn new(max_frame_bytes: u32, max_chunk_bytes: u32) -> ProtocolResult<Self> {
        if max_frame_bytes == 0
            || max_frame_bytes > MAX_FRAME_BYTES
            || max_chunk_bytes == 0
            || max_chunk_bytes > MAX_CHUNK_BYTES
            || max_chunk_bytes > max_frame_bytes
        {
            return Err(ProtocolError::new(
                ErrorCode::LimitExceeded,
                "peer limits exceed protocol bounds",
            ));
        }
        Ok(Self {
            max_frame_bytes,
            max_chunk_bytes,
            supports_reconcile: true,
            supports_idempotent_chunks: true,
        })
    }

    fn validate(&self) -> ProtocolResult<()> {
        Self::new(self.max_frame_bytes, self.max_chunk_bytes).map(|_| ())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    pub versions: Vec<ProtocolVersion>,
    pub capabilities: Capabilities,
}

impl Hello {
    pub fn new(versions: Vec<ProtocolVersion>, capabilities: Capabilities) -> ProtocolResult<Self> {
        let hello = Self {
            versions,
            capabilities,
        };
        hello.validate()?;
        Ok(hello)
    }

    fn validate(&self) -> ProtocolResult<()> {
        if self.versions.is_empty() || self.versions.len() > MAX_SUPPORTED_VERSIONS {
            return Err(ProtocolError::new(
                ErrorCode::LimitExceeded,
                "invalid advertised version count",
            ));
        }
        if self
            .versions
            .iter()
            .enumerate()
            .any(|(index, version)| self.versions[index + 1..].contains(version))
        {
            return Err(ProtocolError::new(
                ErrorCode::InvalidRequest,
                "duplicate advertised version",
            ));
        }
        self.capabilities.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Negotiated {
    pub version: ProtocolVersion,
    pub max_frame_bytes: u32,
    pub max_chunk_bytes: u32,
}

// START_CONTRACT: negotiate
// PURPOSE: Select the highest common version and stricter peer limits.
// INPUTS: { local: &Hello, peer: &Hello }
// OUTPUTS: { ProtocolResult<Negotiated> - effective contract }
// SIDE_EFFECTS: none
// END_CONTRACT: negotiate
pub fn negotiate(local: &Hello, peer: &Hello) -> ProtocolResult<Negotiated> {
    local.validate()?;
    peer.validate()?;
    let version = local
        .versions
        .iter()
        .filter(|candidate| peer.versions.contains(candidate))
        .max()
        .copied()
        .ok_or_else(|| {
            ProtocolError::new(ErrorCode::UnsupportedVersion, "no common protocol version")
        })?;
    Ok(Negotiated {
        version,
        max_frame_bytes: local
            .capabilities
            .max_frame_bytes
            .min(peer.capabilities.max_frame_bytes),
        max_chunk_bytes: local
            .capabilities
            .max_chunk_bytes
            .min(peer.capabilities.max_chunk_bytes),
    })
}

/// Encode the negotiation hello using the same bounded deterministic frame rules as endpoints.
pub fn encode_hello(hello: &Hello) -> ProtocolResult<Vec<u8>> {
    hello.validate()?;
    let bytes = serde_json::to_vec(hello).map_err(|_| frame_error("hello serialization failed"))?;
    if bytes.len() > MAX_FRAME_BYTES as usize {
        return Err(frame_error("hello frame exceeds maximum size"));
    }
    Ok(bytes)
}

/// Decode and validate an untrusted negotiation hello.
pub fn decode_hello(bytes: &[u8]) -> ProtocolResult<Hello> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES as usize {
        return Err(frame_error("hello frame exceeds maximum size"));
    }
    let hello: Hello =
        serde_json::from_slice(bytes).map_err(|_| frame_error("malformed hello JSON"))?;
    hello.validate()?;
    Ok(hello)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub transfer_id: String,
    pub file_name: String,
    pub size_bytes: u64,
    pub sha256: [u8; 32],
    pub modified_at_ms: u64,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

impl Manifest {
    pub fn new(
        transfer_id: String,
        file_name: String,
        size_bytes: u64,
        sha256: [u8; 32],
        modified_at_ms: u64,
    ) -> ProtocolResult<Self> {
        let manifest = Self {
            transfer_id,
            file_name,
            size_bytes,
            sha256,
            modified_at_ms,
            metadata: BTreeMap::new(),
        };
        manifest.validate()?;
        Ok(manifest)
    }

    fn validate(&self) -> ProtocolResult<()> {
        validate_identifier(
            &self.transfer_id,
            MAX_IDENTIFIER_BYTES,
            ErrorCode::InvalidManifest,
        )?;
        if self.file_name.is_empty()
            || self.file_name.len() > MAX_FILENAME_BYTES
            || self.file_name == "."
            || self.file_name == ".."
            || self.file_name.contains('/')
            || self.file_name.contains('\\')
            || self.file_name.bytes().any(|byte| byte < 0x20)
        {
            return Err(ProtocolError::new(
                ErrorCode::InvalidManifest,
                "unsafe source filename",
            ));
        }
        if self.size_bytes > MAX_FILE_BYTES || self.metadata.len() > MAX_METADATA_ENTRIES {
            return Err(ProtocolError::new(
                ErrorCode::LimitExceeded,
                "manifest exceeds protocol bounds",
            ));
        }
        for (key, value) in &self.metadata {
            if key.is_empty()
                || key.len() > MAX_IDENTIFIER_BYTES
                || value.len() > MAX_ERROR_MESSAGE_BYTES
            {
                return Err(ProtocolError::new(
                    ErrorCode::InvalidManifest,
                    "metadata entry exceeds bounds",
                ));
            }
        }
        Ok(())
    }

    pub fn validate_chunk(&self, chunk: &ChunkDescriptor) -> ProtocolResult<()> {
        chunk.validate()?;
        let end = chunk
            .offset
            .checked_add(u64::from(chunk.length))
            .ok_or_else(|| ProtocolError::new(ErrorCode::InvalidChunk, "chunk range overflows"))?;
        if end > self.size_bytes {
            return Err(ProtocolError::new(
                ErrorCode::InvalidChunk,
                "chunk is outside manifest range",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChunkDescriptor {
    pub offset: u64,
    pub length: u32,
    pub sha256: [u8; 32],
}

impl ChunkDescriptor {
    pub fn new(offset: u64, length: u32, sha256: [u8; 32]) -> ProtocolResult<Self> {
        let descriptor = Self {
            offset,
            length,
            sha256,
        };
        descriptor.validate()?;
        Ok(descriptor)
    }

    fn validate(&self) -> ProtocolResult<()> {
        if self.length == 0 || self.length > MAX_CHUNK_BYTES {
            return Err(ProtocolError::new(
                ErrorCode::InvalidChunk,
                "chunk length is outside bounds",
            ));
        }
        self.offset
            .checked_add(u64::from(self.length))
            .ok_or_else(|| ProtocolError::new(ErrorCode::InvalidChunk, "chunk range overflows"))?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusRequest {
    pub client_name: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateTransferRequest {
    pub manifest: Manifest,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconcileRequest {
    pub transfer_id: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadChunkRequest {
    pub transfer_id: String,
    pub chunk: ChunkDescriptor,
    pub payload: Vec<u8>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitRequest {
    pub transfer_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    Status(StatusRequest),
    CreateTransfer(CreateTransferRequest),
    ReconcileTransfer(ReconcileRequest),
    UploadChunk(UploadChunkRequest),
    CommitTransfer(CommitRequest),
}

impl Request {
    pub fn validate(&self) -> ProtocolResult<()> {
        match self {
            Self::Status(request) => validate_identifier(
                &request.client_name,
                MAX_IDENTIFIER_BYTES,
                ErrorCode::InvalidRequest,
            ),
            Self::CreateTransfer(request) => request.manifest.validate(),
            Self::ReconcileTransfer(request) => validate_identifier(
                &request.transfer_id,
                MAX_IDENTIFIER_BYTES,
                ErrorCode::InvalidRequest,
            ),
            Self::UploadChunk(request) => {
                validate_identifier(
                    &request.transfer_id,
                    MAX_IDENTIFIER_BYTES,
                    ErrorCode::InvalidRequest,
                )?;
                request.chunk.validate()?;
                if request.payload.len() != request.chunk.length as usize {
                    return Err(ProtocolError::new(
                        ErrorCode::InvalidChunk,
                        "payload length does not match descriptor",
                    ));
                }
                Ok(())
            }
            Self::CommitTransfer(request) => validate_identifier(
                &request.transfer_id,
                MAX_IDENTIFIER_BYTES,
                ErrorCode::InvalidRequest,
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusResponse {
    pub protocol: ProtocolVersion,
    pub capabilities: Capabilities,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferCreatedResponse {
    pub transfer_id: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconciledResponse {
    pub transfer_id: String,
    pub received: Vec<ChunkDescriptor>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChunkOutcome {
    Accepted,
    AlreadyReceived,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChunkAcceptedResponse {
    pub transfer_id: String,
    pub chunk: ChunkDescriptor,
    pub outcome: ChunkOutcome,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommittedResponse {
    pub transfer_id: String,
    pub size_bytes: u64,
    pub sha256: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Response {
    Status(StatusResponse),
    TransferCreated(TransferCreatedResponse),
    Reconciled(ReconciledResponse),
    ChunkAccepted(ChunkAcceptedResponse),
    Committed(CommittedResponse),
    Error(ProtocolError),
}

impl Response {
    fn validate(&self) -> ProtocolResult<()> {
        match self {
            Self::Status(response) => response.capabilities.validate(),
            Self::TransferCreated(response) => validate_identifier(
                &response.transfer_id,
                MAX_IDENTIFIER_BYTES,
                ErrorCode::InvalidRequest,
            ),
            Self::Reconciled(response) => {
                validate_identifier(
                    &response.transfer_id,
                    MAX_IDENTIFIER_BYTES,
                    ErrorCode::InvalidRequest,
                )?;
                if response.received.len() > MAX_FRAME_BYTES as usize / 64 {
                    return Err(ProtocolError::new(
                        ErrorCode::LimitExceeded,
                        "too many reconciled chunks",
                    ));
                }
                response
                    .received
                    .iter()
                    .try_for_each(ChunkDescriptor::validate)
            }
            Self::ChunkAccepted(response) => {
                validate_identifier(
                    &response.transfer_id,
                    MAX_IDENTIFIER_BYTES,
                    ErrorCode::InvalidRequest,
                )?;
                response.chunk.validate()
            }
            Self::Committed(response) => {
                validate_identifier(
                    &response.transfer_id,
                    MAX_IDENTIFIER_BYTES,
                    ErrorCode::InvalidRequest,
                )?;
                if response.size_bytes > MAX_FILE_BYTES {
                    return Err(ProtocolError::new(
                        ErrorCode::LimitExceeded,
                        "committed size exceeds protocol bounds",
                    ));
                }
                Ok(())
            }
            Self::Error(error) => {
                if error.message.len() > MAX_ERROR_MESSAGE_BYTES {
                    return Err(ProtocolError::new(
                        ErrorCode::LimitExceeded,
                        "error message exceeds protocol bounds",
                    ));
                }
                Ok(())
            }
        }
    }
}

fn validate_identifier(value: &str, max_bytes: usize, code: ErrorCode) -> ProtocolResult<()> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.bytes().any(|byte| !(0x21..=0x7e).contains(&byte))
    {
        return Err(ProtocolError::new(
            code,
            "identifier is empty, oversized, or not printable ASCII",
        ));
    }
    Ok(())
}
fn frame_error(message: impl Into<String>) -> ProtocolError {
    ProtocolError::new(ErrorCode::InvalidFrame, message)
}

// START_CONTRACT: encode_request / decode_request
// PURPOSE: Serialize and validate endpoint requests with deterministic field order and bounded frames.
// INPUTS: { request: &Request | bytes: &[u8] }
// OUTPUTS: { ProtocolResult<Vec<u8>> | ProtocolResult<Request> }
// SIDE_EFFECTS: none
// END_CONTRACT: encode_request / decode_request
pub fn encode_request(request: &Request) -> ProtocolResult<Vec<u8>> {
    request.validate()?;
    let bytes =
        serde_json::to_vec(request).map_err(|_| frame_error("request serialization failed"))?;
    if bytes.len() > MAX_FRAME_BYTES as usize {
        return Err(frame_error("request frame exceeds maximum size"));
    }
    Ok(bytes)
}
pub fn decode_request(bytes: &[u8]) -> ProtocolResult<Request> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES as usize {
        return Err(frame_error("request frame exceeds maximum size"));
    }
    let request: Request =
        serde_json::from_slice(bytes).map_err(|_| frame_error("malformed request JSON"))?;
    request.validate()?;
    Ok(request)
}
pub fn encode_response(response: &Response) -> ProtocolResult<Vec<u8>> {
    response.validate()?;
    let bytes =
        serde_json::to_vec(response).map_err(|_| frame_error("response serialization failed"))?;
    if bytes.len() > MAX_FRAME_BYTES as usize {
        return Err(frame_error("response frame exceeds maximum size"));
    }
    Ok(bytes)
}
pub fn decode_response(bytes: &[u8]) -> ProtocolResult<Response> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES as usize {
        return Err(frame_error("response frame exceeds maximum size"));
    }
    let response: Response =
        serde_json::from_slice(bytes).map_err(|_| frame_error("malformed response JSON"))?;
    response.validate()?;
    Ok(response)
}

#[cfg(test)]
mod contract_tests {
    use super::*;
    fn digest(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    #[test]
    fn deterministic_status_vector_is_frozen() {
        let request = Request::Status(StatusRequest {
            client_name: "watch".into(),
        });
        let bytes = encode_request(&request).expect("status request encodes");
        assert_eq!(bytes, br#"{"op":"status","client_name":"watch"}"#.to_vec());
        assert_eq!(
            decode_request(&bytes).expect("status request decodes"),
            request
        );
    }
    #[test]
    fn manifest_and_chunk_ranges_are_checked() {
        let manifest = Manifest::new(
            "transfer-1".into(),
            "recording.m4a".into(),
            100,
            digest(1),
            1_700_000_000_000,
        )
        .expect("valid manifest");
        assert!(manifest
            .validate_chunk(&ChunkDescriptor::new(100, 1, digest(2)).unwrap())
            .is_err());
        assert!(manifest
            .validate_chunk(&ChunkDescriptor::new(64, 36, digest(3)).unwrap())
            .is_ok());
        assert!(manifest
            .validate_chunk(&ChunkDescriptor::new(64, 37, digest(3)).unwrap())
            .is_err());
    }
    #[test]
    fn upload_requires_exact_bounded_payload() {
        let chunk = ChunkDescriptor::new(0, 3, digest(7)).unwrap();
        let request = Request::UploadChunk(UploadChunkRequest {
            transfer_id: "transfer-1".into(),
            chunk: chunk.clone(),
            payload: vec![1, 2],
        });
        assert!(request.validate().is_err());
        assert!(ChunkDescriptor::new(0, MAX_CHUNK_BYTES + 1, digest(7)).is_err());
    }
    #[test]
    fn negotiation_selects_highest_common_version_and_minimum_limits() {
        let local = Hello::new(
            vec![ProtocolVersion::new(1, 0), ProtocolVersion::new(1, 1)],
            Capabilities::new(MAX_FRAME_BYTES, MAX_CHUNK_BYTES).unwrap(),
        )
        .unwrap();
        let peer = Hello::new(
            vec![ProtocolVersion::new(1, 1), ProtocolVersion::new(2, 0)],
            Capabilities::new(32 * 1024, 16 * 1024).unwrap(),
        )
        .unwrap();
        let negotiated = negotiate(&local, &peer).expect("compatible peers");
        assert_eq!(negotiated.version, ProtocolVersion::new(1, 1));
        assert_eq!(negotiated.max_frame_bytes, 32 * 1024);
        assert_eq!(negotiated.max_chunk_bytes, 16 * 1024);
    }

    #[test]
    fn hello_rejects_non_adjacent_duplicate_versions() {
        assert!(Hello::new(
            vec![
                ProtocolVersion::new(1, 0),
                ProtocolVersion::new(1, 1),
                ProtocolVersion::new(1, 0)
            ],
            Capabilities::new(MAX_FRAME_BYTES, MAX_CHUNK_BYTES).unwrap(),
        )
        .is_err());
    }

    #[test]
    fn hello_wire_vector_is_deterministic_and_bounded() {
        let hello = Hello::new(
            vec![ProtocolVersion::CURRENT],
            Capabilities::new(MAX_FRAME_BYTES, MAX_CHUNK_BYTES).unwrap(),
        )
        .unwrap();
        let bytes = encode_hello(&hello).unwrap();
        assert_eq!(
            bytes,
            br#"{"versions":[{"major":1,"minor":0}],"capabilities":{"max_frame_bytes":131072,"max_chunk_bytes":65536,"supports_reconcile":true,"supports_idempotent_chunks":true}}"#.to_vec()
        );
        assert_eq!(decode_hello(&bytes).unwrap(), hello);
        assert!(decode_hello(&vec![b' '; MAX_FRAME_BYTES as usize + 1]).is_err());
    }
    #[test]
    fn malformed_and_oversized_frames_are_rejected() {
        assert!(decode_request(b"not-json").is_err());
        assert!(decode_request(&vec![b' '; MAX_FRAME_BYTES as usize + 1]).is_err());
        let malformed = br#"{"op":"upload_chunk","transfer_id":"x","chunk":{"offset":0,"length":3,"sha256":[1,2]},"payload":[1,2,3]}"#;
        assert!(decode_request(malformed).is_err());
        let unknown_field = br#"{"op":"status","client_name":"watch","future_field":true}"#;
        assert!(decode_request(unknown_field).is_err());
    }
    #[test]
    fn all_endpoint_operations_have_typed_request_and_response_variants() {
        let requests = [
            Request::Status(StatusRequest {
                client_name: "watch".into(),
            }),
            Request::CreateTransfer(CreateTransferRequest {
                manifest: Manifest::new("t".into(), "a.m4a".into(), 0, digest(1), 0).unwrap(),
            }),
            Request::ReconcileTransfer(ReconcileRequest {
                transfer_id: "t".into(),
            }),
            Request::CommitTransfer(CommitRequest {
                transfer_id: "t".into(),
            }),
        ];
        for request in requests {
            assert!(request.validate().is_ok());
            let decoded = decode_request(&encode_request(&request).unwrap()).unwrap();
            assert_eq!(decoded, request);
        }
    }
}
