//! Windows receiver storage engine, crash-safe chunk journaling, and transfer service.

use openwearsync_protocol::{
    ChunkAcceptedResponse, ChunkDescriptor, ChunkOutcome, CommitRequest, CommittedResponse,
    CreateTransferRequest, ErrorCode, Manifest, ProtocolError, ProtocolResult, ReconcileRequest,
    ReconciledResponse, Request, Response, StatusRequest, StatusResponse, UploadChunkRequest,
    MAX_FILE_BYTES,
};
use openwearsync_security::{AuthToken, PairedPeerRegistry, RateLimiter, ReplayFilter};
use openwearsync_transfer_core::{hash_sha256, TransferReconciliation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

// START_MODULE_CONTRACT
// PURPOSE: Windows receiver storage engine, crash-safe chunk journaling, and transfer service.
// SCOPE: Staged file storage, durable chunk journaling, atomic commit, and authenticated receiver service endpoints.
// DEPENDS: openwearsync-protocol, openwearsync-security, openwearsync-transfer-core, serde, serde_json, sha2
// LINKS: M-WINDOWS-RECEIVER, M-TRANSFER-REGISTRY, V-M-WINDOWS-RECEIVER, DF-RECORDING-MANIFEST, DF-ENCRYPTED-CHUNK-UPLOAD, DF-DURABLE-CHECKPOINT
// END_MODULE_CONTRACT

// START_MODULE_MAP
//   DurableFileStore - crash-safe staging, fsync chunk writing, integrity verification, and atomic final commit.
//   DurableTransferLedger - durable metadata store tracking transfer manifests, acknowledged chunk sets, and commit status.
//   ReceiverService - authenticated request dispatcher enforcing pairing, replay defense, and protocol boundaries.
// END_MODULE_MAP

/// Stored entry in the durable transfer ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerEntry {
    pub manifest: Manifest,
    pub chunks: Vec<ChunkDescriptor>,
    pub committed: bool,
    pub final_path: Option<String>,
}

/// Durable metadata ledger persisting transfer manifests and received chunk lists.
/// Uses atomic write-rename for crash durability.
#[derive(Debug, Clone)]
pub struct DurableTransferLedger {
    ledger_path: PathBuf,
    entries: Arc<Mutex<HashMap<String, LedgerEntry>>>,
}

impl DurableTransferLedger {
    // START_CONTRACT: DurableTransferLedger::open
    // PURPOSE: Load existing ledger state from disk or create a fresh durable store.
    // INPUTS: { ledger_path: impl AsRef<Path> }
    // OUTPUTS: { io::Result<Self> }
    // SIDE_EFFECTS: creates parent directories, reads JSON journal if present.
    // END_CONTRACT: DurableTransferLedger::open
    pub fn open(ledger_path: impl AsRef<Path>) -> std::io::Result<Self> {
        let ledger_path = ledger_path.as_ref().to_path_buf();
        if let Some(parent) = ledger_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut entries = HashMap::new();
        if ledger_path.exists() {
            if let Ok(bytes) = fs::read(&ledger_path) {
                if let Ok(loaded) = serde_json::from_slice::<HashMap<String, LedgerEntry>>(&bytes) {
                    entries = loaded;
                }
            }
        }

        Ok(Self {
            ledger_path,
            entries: Arc::new(Mutex::new(entries)),
        })
    }

    /// Persist current entries to disk atomically using temporary file rename.
    fn persist_locked(&self, entries: &HashMap<String, LedgerEntry>) -> ProtocolResult<()> {
        let temp_path = self.ledger_path.with_extension("tmp");
        let bytes = serde_json::to_vec(entries).map_err(|e| ProtocolError {
            code: ErrorCode::LimitExceeded,
            message: format!("ledger serialization failed: {}", e),
        })?;

        {
            let mut file = File::create(&temp_path).map_err(|e| ProtocolError {
                code: ErrorCode::LimitExceeded,
                message: format!("cannot create ledger temp file: {}", e),
            })?;
            file.write_all(&bytes).map_err(|e| ProtocolError {
                code: ErrorCode::LimitExceeded,
                message: format!("cannot write ledger: {}", e),
            })?;
            file.sync_all().map_err(|e| ProtocolError {
                code: ErrorCode::LimitExceeded,
                message: format!("cannot fsync ledger: {}", e),
            })?;
        }

        fs::rename(&temp_path, &self.ledger_path).map_err(|e| ProtocolError {
            code: ErrorCode::LimitExceeded,
            message: format!("cannot atomically commit ledger: {}", e),
        })?;

        Ok(())
    }

    pub fn insert_transfer(&self, manifest: Manifest) -> ProtocolResult<()> {
        let mut map = self.entries.lock().unwrap();
        if map.contains_key(&manifest.transfer_id) {
            return Err(ProtocolError {
                code: ErrorCode::Conflict,
                message: "transfer already exists in ledger".to_string(),
            });
        }

        map.insert(
            manifest.transfer_id.clone(),
            LedgerEntry {
                manifest,
                chunks: Vec::new(),
                committed: false,
                final_path: None,
            },
        );

        self.persist_locked(&map)
    }

    pub fn get_manifest(&self, transfer_id: &str) -> Option<Manifest> {
        let map = self.entries.lock().unwrap();
        map.get(transfer_id).map(|e| e.manifest.clone())
    }

    pub fn get_chunks(&self, transfer_id: &str) -> Vec<ChunkDescriptor> {
        let map = self.entries.lock().unwrap();
        map.get(transfer_id)
            .map(|e| e.chunks.clone())
            .unwrap_or_default()
    }

    pub fn record_chunk(
        &self,
        transfer_id: &str,
        chunk: ChunkDescriptor,
    ) -> ProtocolResult<ChunkOutcome> {
        let mut map = self.entries.lock().unwrap();
        let entry = map.get_mut(transfer_id).ok_or_else(|| ProtocolError {
            code: ErrorCode::TransferNotFound,
            message: "transfer not registered in ledger".to_string(),
        })?;

        if entry.committed {
            return Err(ProtocolError {
                code: ErrorCode::AlreadyCommitted,
                message: "transfer already committed".to_string(),
            });
        }

        if entry.chunks.iter().any(|c| c.offset == chunk.offset) {
            return Ok(ChunkOutcome::AlreadyReceived);
        }

        entry.chunks.push(chunk);
        self.persist_locked(&map)?;
        Ok(ChunkOutcome::Accepted)
    }

    pub fn mark_committed(&self, transfer_id: &str, final_path: &str) -> ProtocolResult<()> {
        let mut map = self.entries.lock().unwrap();
        let entry = map.get_mut(transfer_id).ok_or_else(|| ProtocolError {
            code: ErrorCode::TransferNotFound,
            message: "transfer not found in ledger".to_string(),
        })?;

        entry.committed = true;
        entry.final_path = Some(final_path.to_string());
        self.persist_locked(&map)
    }

    pub fn is_committed(&self, transfer_id: &str) -> bool {
        let map = self.entries.lock().unwrap();
        map.get(transfer_id).map(|e| e.committed).unwrap_or(false)
    }
}

/// Durable file storage handling staging, fsync chunk writing, digest checking, and atomic publication.
pub struct DurableFileStore {
    staging_dir: PathBuf,
    destination_dir: PathBuf,
    ledger: DurableTransferLedger,
}

impl DurableFileStore {
    // START_CONTRACT: DurableFileStore::new
    // PURPOSE: Initialize file store ensuring directories and ledger are accessible.
    // INPUTS: { staging_dir: PathBuf, destination_dir: PathBuf, ledger: DurableTransferLedger }
    // OUTPUTS: { std::io::Result<Self> }
    // SIDE_EFFECTS: creates staging and destination folders.
    // END_CONTRACT: DurableFileStore::new
    pub fn new(
        staging_dir: PathBuf,
        destination_dir: PathBuf,
        ledger: DurableTransferLedger,
    ) -> std::io::Result<Self> {
        fs::create_dir_all(&staging_dir)?;
        fs::create_dir_all(&destination_dir)?;
        Ok(Self {
            staging_dir,
            destination_dir,
            ledger,
        })
    }

    fn staging_file_path(&self, transfer_id: &str) -> PathBuf {
        self.staging_dir.join(format!("{}.part", transfer_id))
    }

    // START_CONTRACT: DurableFileStore::init_transfer
    // PURPOSE: Register transfer manifest and allocate staging file.
    // INPUTS: { manifest: Manifest }
    // OUTPUTS: { ProtocolResult<()> }
    // SIDE_EFFECTS: writes ledger entry and initializes staging file.
    // END_CONTRACT: DurableFileStore::init_transfer
    pub fn init_transfer(&self, manifest: Manifest) -> ProtocolResult<()> {
        if manifest.size_bytes > MAX_FILE_BYTES {
            return Err(ProtocolError {
                code: ErrorCode::LimitExceeded,
                message: "file exceeds max allowed size".to_string(),
            });
        }

        self.ledger.insert_transfer(manifest.clone())?;

        let staging_path = self.staging_file_path(&manifest.transfer_id);
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .open(&staging_path)
            .map_err(|e| ProtocolError {
                code: ErrorCode::LimitExceeded,
                message: format!("cannot open staging file: {}", e),
            })?;

        // Pre-allocate or truncate
        file.set_len(manifest.size_bytes).map_err(|e| ProtocolError {
            code: ErrorCode::LimitExceeded,
            message: format!("cannot pre-allocate staging file: {}", e),
        })?;

        Ok(())
    }

    // START_CONTRACT: DurableFileStore::write_chunk
    // PURPOSE: Write chunk at offset, fsync to disk, and journal in ledger.
    // INPUTS: { transfer_id: &str, descriptor: &ChunkDescriptor, payload: &[u8] }
    // OUTPUTS: { ProtocolResult<ChunkOutcome> }
    // SIDE_EFFECTS: writes payload to disk, syncs file to OS storage, updates ledger.
    // END_CONTRACT: DurableFileStore::write_chunk
    pub fn write_chunk(
        &self,
        transfer_id: &str,
        descriptor: &ChunkDescriptor,
        payload: &[u8],
    ) -> ProtocolResult<ChunkOutcome> {
        if descriptor.length as usize != payload.len() {
            return Err(ProtocolError {
                code: ErrorCode::InvalidChunk,
                message: "descriptor length does not match payload".to_string(),
            });
        }

        let computed_chunk_sha = hash_sha256(payload);
        if computed_chunk_sha != descriptor.sha256 {
            return Err(ProtocolError {
                code: ErrorCode::InvalidChunk,
                message: "chunk sha256 mismatch".to_string(),
            });
        }

        let staging_path = self.staging_file_path(transfer_id);
        if !staging_path.exists() {
            return Err(ProtocolError {
                code: ErrorCode::TransferNotFound,
                message: "staging file not found".to_string(),
            });
        }

        let mut file = OpenOptions::new()
            .write(true)
            .open(&staging_path)
            .map_err(|e| ProtocolError {
                code: ErrorCode::LimitExceeded,
                message: format!("cannot open staging file: {}", e),
            })?;

        file.seek(SeekFrom::Start(descriptor.offset))
            .map_err(|e| ProtocolError {
                code: ErrorCode::LimitExceeded,
                message: format!("seek failed: {}", e),
            })?;

        file.write_all(payload).map_err(|e| ProtocolError {
            code: ErrorCode::LimitExceeded,
            message: format!("write failed: {}", e),
        })?;

        // Force disk flush before journal ack
        file.sync_all().map_err(|e| ProtocolError {
            code: ErrorCode::LimitExceeded,
            message: format!("fsync failed: {}", e),
        })?;

        self.ledger.record_chunk(transfer_id, descriptor.clone())
    }

    // START_CONTRACT: DurableFileStore::finalize_transfer
    // PURPOSE: Verify full file integrity and atomically move to final destination.
    // INPUTS: { transfer_id: &str }
    // OUTPUTS: { ProtocolResult<CommittedResponse> }
    // SIDE_EFFECTS: verifies entire file hash, renames part file to final file, updates ledger.
    // END_CONTRACT: DurableFileStore::finalize_transfer
    pub fn finalize_transfer(&self, transfer_id: &str) -> ProtocolResult<CommittedResponse> {
        let manifest = self.ledger.get_manifest(transfer_id).ok_or_else(|| {
            ProtocolError {
                code: ErrorCode::TransferNotFound,
                message: "transfer not found".to_string(),
            }
        })?;

        if self.ledger.is_committed(transfer_id) {
            return Ok(CommittedResponse {
                transfer_id: transfer_id.to_string(),
                size_bytes: manifest.size_bytes,
                sha256: manifest.sha256,
            });
        }

        // Verify that all chunks have been received and form a complete interval
        let chunks = self.ledger.get_chunks(transfer_id);
        let mut rec = TransferReconciliation::new(manifest.size_bytes);
        for c in chunks {
            rec.record_chunk(c.offset, c.length);
        }

        if !rec.is_complete() {
            return Err(ProtocolError {
                code: ErrorCode::Conflict,
                message: "transfer is incomplete, cannot finalize".to_string(),
            });
        }

        // Compute entire staging file SHA-256
        let staging_path = self.staging_file_path(transfer_id);
        let mut file = File::open(&staging_path).map_err(|e| ProtocolError {
            code: ErrorCode::TransferNotFound,
            message: format!("cannot open staging file for verification: {}", e),
        })?;

        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        let mut total_read = 0u64;

        loop {
            let n = file.read(&mut buffer).map_err(|e| ProtocolError {
                code: ErrorCode::InvalidFrame,
                message: format!("read error during hash verification: {}", e),
            })?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
            total_read += n as u64;
        }

        if total_read != manifest.size_bytes {
            return Err(ProtocolError {
                code: ErrorCode::InvalidManifest,
                message: "staged file size does not match manifest".to_string(),
            });
        }

        let actual_sha: [u8; 32] = hasher.finalize().into();
        if actual_sha != manifest.sha256 {
            return Err(ProtocolError {
                code: ErrorCode::InvalidManifest,
                message: "staged file checksum does not match manifest".to_string(),
            });
        }

        // Atomic publish to destination dir
        let final_path = self.destination_dir.join(&manifest.file_name);
        fs::rename(&staging_path, &final_path).map_err(|e| ProtocolError {
            code: ErrorCode::LimitExceeded,
            message: format!("cannot atomically commit final file: {}", e),
        })?;

        self.ledger
            .mark_committed(transfer_id, final_path.to_str().unwrap_or(""))?;

        Ok(CommittedResponse {
            transfer_id: transfer_id.to_string(),
            size_bytes: manifest.size_bytes,
            sha256: manifest.sha256,
        })
    }

    pub fn ledger(&self) -> &DurableTransferLedger {
        &self.ledger
    }
}

/// Windows receiver service dispatching authenticated transfer requests.
pub struct ReceiverService {
    store: Arc<DurableFileStore>,
    registry: Arc<PairedPeerRegistry>,
    limiter: RateLimiter,
    replay_filter: ReplayFilter,
    max_concurrent_transfers: usize,
    active_transfers: Arc<Mutex<HashSet<String>>>,
}

impl ReceiverService {
    // START_CONTRACT: ReceiverService::new
    // PURPOSE: Initialize the receiver service with security policies, storage, and limits.
    // INPUTS: { store: Arc<DurableFileStore>, registry: Arc<PairedPeerRegistry>, max_concurrent: usize }
    // OUTPUTS: { Self }
    // SIDE_EFFECTS: none
    // END_CONTRACT: ReceiverService::new
    pub fn new(
        store: Arc<DurableFileStore>,
        registry: Arc<PairedPeerRegistry>,
        max_concurrent_transfers: usize,
    ) -> Self {
        Self {
            store,
            registry,
            limiter: RateLimiter::new(5, Duration::from_secs(60)),
            replay_filter: ReplayFilter::new(),
            max_concurrent_transfers,
            active_transfers: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Authenticate request from a paired peer token.
    pub fn authenticate(&self, token: &AuthToken) -> ProtocolResult<()> {
        self.limiter.check_allowed(&token.device_id)?;

        let secret = match self.registry.get_secret(&token.device_id) {
            Some(s) => s,
            None => {
                let _ = self.limiter.record_failure(&token.device_id);
                return Err(ProtocolError {
                    code: ErrorCode::InvalidRequest,
                    message: "device is not paired or has been revoked".to_string(),
                });
            }
        };

        if let Err(e) = token.verify(&secret, Duration::from_secs(120)) {
            let _ = self.limiter.record_failure(&token.device_id);
            return Err(e);
        }

        self.replay_filter.check_and_mark(&token.nonce)?;
        self.limiter.record_success(&token.device_id);
        Ok(())
    }

    // START_CONTRACT: ReceiverService::handle_request
    // PURPOSE: Dispatch and execute a typed protocol request.
    // INPUTS: { request: Request, auth_token: Option<&AuthToken> }
    // OUTPUTS: { ProtocolResult<Response> }
    // SIDE_EFFECTS: modifies store and ledger according to request.
    // END_CONTRACT: ReceiverService::handle_request
    pub fn handle_request(
        &self,
        request: Request,
        auth_token: Option<&AuthToken>,
    ) -> ProtocolResult<Response> {
        request.validate()?;

        // Status does not require authentication
        if let Request::Status(ref req) = request {
            return self.handle_status(req);
        }

        // All other transfer operations require a valid authentication token
        let token = auth_token.ok_or_else(|| ProtocolError {
            code: ErrorCode::InvalidRequest,
            message: "authentication token required".to_string(),
        })?;
        self.authenticate(token)?;

        match request {
            Request::Status(_) => unreachable!(),
            Request::CreateTransfer(req) => self.handle_create(req),
            Request::ReconcileTransfer(req) => self.handle_reconcile(req),
            Request::UploadChunk(req) => self.handle_upload(req),
            Request::CommitTransfer(req) => self.handle_commit(req),
        }
    }

    fn handle_status(&self, _req: &StatusRequest) -> ProtocolResult<Response> {
        Ok(Response::Status(StatusResponse {
            protocol: openwearsync_protocol::ProtocolVersion::CURRENT,
            capabilities: openwearsync_protocol::Capabilities::new(
                openwearsync_protocol::MAX_FRAME_BYTES,
                openwearsync_protocol::MAX_CHUNK_BYTES,
            )?,
        }))
    }

    fn handle_create(&self, req: CreateTransferRequest) -> ProtocolResult<Response> {
        let mut active = self.active_transfers.lock().unwrap();
        if active.len() >= self.max_concurrent_transfers {
            return Err(ProtocolError {
                code: ErrorCode::LimitExceeded,
                message: "max concurrent transfers exceeded".to_string(),
            });
        }

        let id = req.manifest.transfer_id.clone();
        if let Err(e) = self.store.init_transfer(req.manifest) {
            if e.code == ErrorCode::Conflict {
                // Already created, return conflict for client to reconcile
                return Ok(Response::Error(e));
            }
            return Err(e);
        }

        active.insert(id.clone());
        Ok(Response::TransferCreated(
            openwearsync_protocol::TransferCreatedResponse { transfer_id: id },
        ))
    }

    fn handle_reconcile(&self, req: ReconcileRequest) -> ProtocolResult<Response> {
        let received = self.store.ledger().get_chunks(&req.transfer_id);
        Ok(Response::Reconciled(ReconciledResponse {
            transfer_id: req.transfer_id,
            received,
        }))
    }

    fn handle_upload(&self, req: UploadChunkRequest) -> ProtocolResult<Response> {
        let outcome = self
            .store
            .write_chunk(&req.transfer_id, &req.chunk, &req.payload)?;
        Ok(Response::ChunkAccepted(ChunkAcceptedResponse {
            transfer_id: req.transfer_id,
            chunk: req.chunk,
            outcome,
        }))
    }

    fn handle_commit(&self, req: CommitRequest) -> ProtocolResult<Response> {
        let res = self.store.finalize_transfer(&req.transfer_id)?;
        let mut active = self.active_transfers.lock().unwrap();
        active.remove(&req.transfer_id);
        Ok(Response::Committed(res))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openwearsync_security::PairedPeer;
    use tempfile::tempdir;

    #[test]
    fn durable_file_store_stages_chunks_fsyncs_and_atomically_commits() {
        let temp = tempdir().unwrap();
        let ledger_path = temp.path().join("ledger.json");
        let staging_dir = temp.path().join("staging");
        let dest_dir = temp.path().join("recordings");

        let ledger = DurableTransferLedger::open(&ledger_path).unwrap();
        let store = DurableFileStore::new(staging_dir, dest_dir.clone(), ledger).unwrap();

        let payload = vec![0x33u8; 100_000];
        let sha256 = hash_sha256(&payload);
        let manifest = Manifest::new(
            "transfer-durable-1".to_string(),
            "recording.m4a".to_string(),
            payload.len() as u64,
            sha256,
            1700000000,
        )
        .unwrap();

        store.init_transfer(manifest.clone()).unwrap();

        // Write chunk 1: 0..64KB
        let chunk1_data = &payload[..64 * 1024];
        let chunk1_desc = ChunkDescriptor::new(0, chunk1_data.len() as u32, hash_sha256(chunk1_data)).unwrap();
        let outcome1 = store.write_chunk("transfer-durable-1", &chunk1_desc, chunk1_data).unwrap();
        assert_eq!(outcome1, ChunkOutcome::Accepted);

        // Duplicate chunk 1 write returns AlreadyReceived
        let outcome1_dup = store.write_chunk("transfer-durable-1", &chunk1_desc, chunk1_data).unwrap();
        assert_eq!(outcome1_dup, ChunkOutcome::AlreadyReceived);

        // Attempting to finalize incomplete transfer fails
        assert!(store.finalize_transfer("transfer-durable-1").is_err());

        // Write chunk 2: 64KB..100KB
        let chunk2_data = &payload[64 * 1024..];
        let chunk2_desc = ChunkDescriptor::new(64 * 1024, chunk2_data.len() as u32, hash_sha256(chunk2_data)).unwrap();
        let outcome2 = store.write_chunk("transfer-durable-1", &chunk2_desc, chunk2_data).unwrap();
        assert_eq!(outcome2, ChunkOutcome::Accepted);

        // Finalize completes atomically
        let committed = store.finalize_transfer("transfer-durable-1").unwrap();
        assert_eq!(committed.size_bytes, 100_000);
        assert_eq!(committed.sha256, sha256);

        // Final file exists in destination directory with exact contents
        let final_file = dest_dir.join("recording.m4a");
        assert!(final_file.exists());
        assert_eq!(fs::read(final_file).unwrap(), payload);

        // Idempotent commit returns ok
        let committed_again = store.finalize_transfer("transfer-durable-1").unwrap();
        assert_eq!(committed_again.size_bytes, 100_000);
    }

    #[test]
    fn durable_ledger_reloads_after_restart() {
        let temp = tempdir().unwrap();
        let ledger_path = temp.path().join("ledger.json");

        {
            let ledger = DurableTransferLedger::open(&ledger_path).unwrap();
            let manifest = Manifest::new(
                "transfer-restart-1".to_string(),
                "test.m4a".to_string(),
                1000,
                [0u8; 32],
                1700000000,
            )
            .unwrap();
            ledger.insert_transfer(manifest).unwrap();
            let chunk = ChunkDescriptor::new(0, 500, [1u8; 32]).unwrap();
            ledger.record_chunk("transfer-restart-1", chunk).unwrap();
        }

        // Reload
        let reloaded = DurableTransferLedger::open(&ledger_path).unwrap();
        let chunks = reloaded.get_chunks("transfer-restart-1");
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].length, 500);
    }

    #[test]
    fn receiver_service_enforces_auth_and_rejects_unpaired_client() {
        let temp = tempdir().unwrap();
        let ledger = DurableTransferLedger::open(temp.path().join("ledger.json")).unwrap();
        let store = Arc::new(DurableFileStore::new(
            temp.path().join("staging"),
            temp.path().join("dest"),
            ledger,
        ).unwrap());

        let registry = Arc::new(PairedPeerRegistry::new());
        let service = ReceiverService::new(store, registry.clone(), 4);

        let manifest = Manifest::new(
            "transfer-unpaired".to_string(),
            "test.m4a".to_string(),
            100,
            [0u8; 32],
            1700000000,
        )
        .unwrap();
        let create_req = Request::CreateTransfer(CreateTransferRequest { manifest });

        // Missing auth token
        let res_no_auth = service.handle_request(create_req.clone(), None);
        assert!(res_no_auth.is_err());

        // Token from unregistered device
        let fake_token = AuthToken::create("unpaired-watch", &[0xAAu8; 32]);
        let res_unpaired = service.handle_request(create_req.clone(), Some(&fake_token));
        assert!(res_unpaired.is_err());

        // Enroll device
        let secret = [0x55u8; 32];
        registry.enroll(PairedPeer {
            device_id: "paired-watch".to_string(),
            device_name: "Watch 7".to_string(),
            shared_secret: secret,
            enrolled_at_epoch_s: 1700000000,
            revoked: false,
        });

        let valid_token = AuthToken::create("paired-watch", &secret);
        let res_ok = service.handle_request(create_req, Some(&valid_token));
        assert!(res_ok.is_ok());

        // Replayed token is rejected
        let res_replay = service.handle_request(
            Request::ReconcileTransfer(ReconcileRequest { transfer_id: "transfer-unpaired".to_string() }),
            Some(&valid_token),
        );
        assert!(res_replay.is_err());
    }
}
