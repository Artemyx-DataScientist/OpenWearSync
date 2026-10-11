//! Windows receiver storage engine, crash-safe chunk journaling, and transfer service.

use openwearsync_protocol::{
    ChunkAcceptedResponse, ChunkDescriptor, ChunkOutcome, CommitRequest, CommittedResponse,
    CreateTransferRequest, ErrorCode, Manifest, ProtocolError, ProtocolResult, ReconcileRequest,
    ReconciledResponse, Request, Response, StatusRequest, StatusResponse, UploadChunkRequest,
    MAX_FILE_BYTES,
};
use openwearsync_security::{
    AuthToken, PairedPeer, PairedPeerRegistry, PairingSession, RateLimiter, ReplayFilter,
    ServerIdentity,
};
use openwearsync_transfer_core::{hash_sha256, TransferReconciliation};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

pub mod server;
pub use server::HttpServer;

// START_MODULE_CONTRACT
// PURPOSE: Windows receiver storage engine, crash-safe chunk journaling, SQLite ledger, and transfer service.
// SCOPE: Staged file storage, durable SQLite chunk journaling, atomic commit, and authenticated receiver service endpoints.
// DEPENDS: openwearsync-protocol, openwearsync-security, openwearsync-transfer-core, rusqlite, serde, serde_json, sha2
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

/// Durable metadata ledger persisting transfer manifests and received chunk lists in SQLite.
/// Uses SQLite WAL mode with synchronous=NORMAL and foreign key integrity.
/// Fails closed if the database cannot be opened or is corrupted.
#[derive(Clone)]
pub struct DurableTransferLedger {
    db_path: PathBuf,
    conn: Arc<Mutex<Connection>>,
}

impl std::fmt::Debug for DurableTransferLedger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DurableTransferLedger")
            .field("db_path", &self.db_path)
            .finish()
    }
}

impl DurableTransferLedger {
    // START_CONTRACT: DurableTransferLedger::open
    // PURPOSE: Load existing SQLite ledger state from disk or create fresh schema.
    // INPUTS: { ledger_path: impl AsRef<Path> }
    // OUTPUTS: { io::Result<Self> }
    // SIDE_EFFECTS: creates parent directories, opens SQLite database, runs WAL pragmas and migrations.
    // END_CONTRACT: DurableTransferLedger::open
    pub fn open(ledger_path: impl AsRef<Path>) -> std::io::Result<Self> {
        let db_path = ledger_path.as_ref().to_path_buf();
        if let Some(parent) = db_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(&db_path).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, format!("failed to open sqlite ledger: {}", e))
        })?;

        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;
             CREATE TABLE IF NOT EXISTS transfers (
                 transfer_id TEXT PRIMARY KEY,
                 file_name TEXT NOT NULL,
                 size_bytes INTEGER NOT NULL,
                 sha256 BLOB NOT NULL,
                 modified_at_ms INTEGER NOT NULL,
                 committed INTEGER NOT NULL DEFAULT 0,
                 final_path TEXT
             );
             CREATE TABLE IF NOT EXISTS chunks (
                 transfer_id TEXT NOT NULL,
                 offset INTEGER NOT NULL,
                 length INTEGER NOT NULL,
                 sha256 BLOB NOT NULL,
                 PRIMARY KEY (transfer_id, offset),
                 FOREIGN KEY (transfer_id) REFERENCES transfers(transfer_id) ON DELETE CASCADE
             );
             CREATE TABLE IF NOT EXISTS peers (
                 device_id TEXT PRIMARY KEY,
                 device_name TEXT NOT NULL,
                 shared_secret BLOB NOT NULL,
                 enrolled_at_epoch_s INTEGER NOT NULL,
                 revoked INTEGER NOT NULL DEFAULT 0
             );
             CREATE TABLE IF NOT EXISTS server_identity (
                 key TEXT PRIMARY KEY,
                 val TEXT NOT NULL
             );"
        ).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, format!("failed to initialize sqlite schema: {}", e))
        })?;

        Ok(Self {
            db_path,
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn insert_transfer(&self, manifest: Manifest) -> ProtocolResult<()> {
        let conn = self.conn.lock().unwrap();
        let exists: bool = conn
            .query_row(
                "SELECT 1 FROM transfers WHERE transfer_id = ?1",
                params![manifest.transfer_id],
                |_| Ok(true),
            )
            .optional()
            .map_err(|e| ProtocolError {
                code: ErrorCode::LimitExceeded,
                message: format!("sqlite query error: {}", e),
            })?
            .unwrap_or(false);

        if exists {
            return Err(ProtocolError {
                code: ErrorCode::Conflict,
                message: "transfer already exists in ledger".to_string(),
            });
        }

        conn.execute(
            "INSERT INTO transfers (transfer_id, file_name, size_bytes, sha256, modified_at_ms, committed, final_path) VALUES (?1, ?2, ?3, ?4, ?5, 0, NULL)",
            params![
                manifest.transfer_id,
                manifest.file_name,
                manifest.size_bytes as i64,
                &manifest.sha256[..],
                manifest.modified_at_ms as i64,
            ],
        )
        .map_err(|e| ProtocolError {
            code: ErrorCode::LimitExceeded,
            message: format!("sqlite insert transfer error: {}", e),
        })?;

        Ok(())
    }

    pub fn get_manifest(&self, transfer_id: &str) -> Option<Manifest> {
        let conn = self.conn.lock().unwrap();
        let row = conn
            .query_row(
                "SELECT file_name, size_bytes, sha256, modified_at_ms FROM transfers WHERE transfer_id = ?1",
                params![transfer_id],
                |r| {
                    let file_name: String = r.get(0)?;
                    let size_bytes: i64 = r.get(1)?;
                    let sha256_blob: Vec<u8> = r.get(2)?;
                    let modified_at: i64 = r.get(3)?;
                    Ok((file_name, size_bytes, sha256_blob, modified_at))
                },
            )
            .optional()
            .ok()
            .flatten();

        row.and_then(|(file_name, size_bytes, sha256_blob, modified_at)| {
            let mut sha256 = [0u8; 32];
            if sha256_blob.len() == 32 {
                sha256.copy_from_slice(&sha256_blob);
            }
            Manifest::new(
                transfer_id.to_string(),
                file_name,
                size_bytes as u64,
                sha256,
                modified_at as u64,
            )
            .ok()
        })
    }


    pub fn get_chunks(&self, transfer_id: &str) -> Vec<ChunkDescriptor> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = match conn.prepare(
            "SELECT offset, length, sha256 FROM chunks WHERE transfer_id = ?1 ORDER BY offset ASC",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let rows = stmt.query_map(params![transfer_id], |r| {
            let offset: i64 = r.get(0)?;
            let length: i64 = r.get(1)?;
            let sha256_blob: Vec<u8> = r.get(2)?;
            Ok((offset, length, sha256_blob))
        });

        match rows {
            Ok(iter) => {
                let mut chunks = Vec::new();
                for item in iter.flatten() {
                    let mut sha256 = [0u8; 32];
                    if item.2.len() == 32 {
                        sha256.copy_from_slice(&item.2);
                    }
                    if let Ok(c) = ChunkDescriptor::new(item.0 as u64, item.1 as u32, sha256) {
                        chunks.push(c);
                    }
                }
                chunks
            }
            Err(_) => Vec::new(),
        }
    }

    pub fn record_chunk(
        &self,
        transfer_id: &str,
        chunk: ChunkDescriptor,
    ) -> ProtocolResult<ChunkOutcome> {
        let conn = self.conn.lock().unwrap();
        let status: Option<(i32,)> = conn
            .query_row(
                "SELECT committed FROM transfers WHERE transfer_id = ?1",
                params![transfer_id],
                |r| Ok((r.get(0)?,)),
            )
            .optional()
            .map_err(|e| ProtocolError {
                code: ErrorCode::LimitExceeded,
                message: format!("sqlite query error: {}", e),
            })?;

        let (committed,) = status.ok_or_else(|| ProtocolError {
            code: ErrorCode::TransferNotFound,
            message: "transfer not registered in ledger".to_string(),
        })?;

        if committed != 0 {
            return Err(ProtocolError {
                code: ErrorCode::AlreadyCommitted,
                message: "transfer already committed".to_string(),
            });
        }

        let chunk_exists: bool = conn
            .query_row(
                "SELECT 1 FROM chunks WHERE transfer_id = ?1 AND offset = ?2",
                params![transfer_id, chunk.offset as i64],
                |_| Ok(true),
            )
            .optional()
            .map_err(|e| ProtocolError {
                code: ErrorCode::LimitExceeded,
                message: format!("sqlite query error: {}", e),
            })?
            .unwrap_or(false);

        if chunk_exists {
            return Ok(ChunkOutcome::AlreadyReceived);
        }

        conn.execute(
            "INSERT INTO chunks (transfer_id, offset, length, sha256) VALUES (?1, ?2, ?3, ?4)",
            params![
                transfer_id,
                chunk.offset as i64,
                chunk.length as i64,
                &chunk.sha256[..],
            ],
        )
        .map_err(|e| ProtocolError {
            code: ErrorCode::LimitExceeded,
            message: format!("sqlite insert chunk error: {}", e),
        })?;

        Ok(ChunkOutcome::Accepted)
    }

    pub fn mark_committed(&self, transfer_id: &str, final_path: &str) -> ProtocolResult<()> {
        let conn = self.conn.lock().unwrap();
        let rows_affected = conn
            .execute(
                "UPDATE transfers SET committed = 1, final_path = ?1 WHERE transfer_id = ?2",
                params![final_path, transfer_id],
            )
            .map_err(|e| ProtocolError {
                code: ErrorCode::LimitExceeded,
                message: format!("sqlite update committed error: {}", e),
            })?;

        if rows_affected == 0 {
            return Err(ProtocolError {
                code: ErrorCode::TransferNotFound,
                message: "transfer not found in ledger".to_string(),
            });
        }
        Ok(())
    }

    pub fn is_committed(&self, transfer_id: &str) -> bool {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT committed FROM transfers WHERE transfer_id = ?1",
            params![transfer_id],
            |r| {
                let c: i32 = r.get(0)?;
                Ok(c == 1)
            },
        )
        .optional()
        .ok()
        .flatten()
        .unwrap_or(false)
    }

    pub fn list_transfers(&self) -> Vec<LedgerEntry> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = match conn.prepare(
            "SELECT transfer_id, file_name, size_bytes, sha256, modified_at_ms, committed, final_path FROM transfers ORDER BY modified_at_ms DESC",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let rows = stmt.query_map([], |r| {
            let transfer_id: String = r.get(0)?;
            let file_name: String = r.get(1)?;
            let size_bytes: i64 = r.get(2)?;
            let sha256_blob: Vec<u8> = r.get(3)?;
            let modified_at: i64 = r.get(4)?;
            let committed_i32: i32 = r.get(5)?;
            let final_path: Option<String> = r.get(6)?;
            Ok((transfer_id, file_name, size_bytes, sha256_blob, modified_at, committed_i32 != 0, final_path))
        });

        match rows {
            Ok(iter) => {
                let mut entries = Vec::new();
                for item in iter.flatten() {
                    let mut sha256 = [0u8; 32];
                    if item.3.len() == 32 {
                        sha256.copy_from_slice(&item.3);
                    }
                    if let Ok(manifest) = Manifest::new(
                        item.0.clone(),
                        item.1,
                        item.2 as u64,
                        sha256,
                        item.4 as u64,
                    ) {
                        entries.push(LedgerEntry {
                            manifest,
                            chunks: Vec::new(),
                            committed: item.5,
                            final_path: item.6,
                        });
                    }
                }
                entries
            }
            Err(_) => Vec::new(),
        }
    }

    pub fn save_peer(&self, peer: &PairedPeer) -> ProtocolResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO peers (device_id, device_name, shared_secret, enrolled_at_epoch_s, revoked)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                peer.device_id,
                peer.device_name,
                &peer.shared_secret[..],
                peer.enrolled_at_epoch_s as i64,
                if peer.revoked { 1 } else { 0 },
            ],
        )
        .map_err(|e| ProtocolError {
            code: ErrorCode::LimitExceeded,
            message: format!("sqlite save peer error: {}", e),
        })?;
        Ok(())
    }

    pub fn load_peers(&self) -> ProtocolResult<Vec<PairedPeer>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT device_id, device_name, shared_secret, enrolled_at_epoch_s, revoked FROM peers")
            .map_err(|e| ProtocolError {
                code: ErrorCode::LimitExceeded,
                message: format!("sqlite prepare load_peers error: {}", e),
            })?;

        let rows = stmt
            .query_map([], |r| {
                let device_id: String = r.get(0)?;
                let device_name: String = r.get(1)?;
                let secret_blob: Vec<u8> = r.get(2)?;
                let enrolled: i64 = r.get(3)?;
                let revoked: i32 = r.get(4)?;
                Ok((device_id, device_name, secret_blob, enrolled, revoked))
            })
            .map_err(|e| ProtocolError {
                code: ErrorCode::LimitExceeded,
                message: format!("sqlite query load_peers error: {}", e),
            })?;

        let mut peers = Vec::new();
        for item in rows.flatten() {
            let mut secret = [0u8; 32];
            if item.2.len() == 32 {
                secret.copy_from_slice(&item.2);
            }
            peers.push(PairedPeer {
                device_id: item.0,
                device_name: item.1,
                shared_secret: secret,
                enrolled_at_epoch_s: item.3 as u64,
                revoked: item.4 != 0,
            });
        }
        Ok(peers)
    }

    pub fn revoke_peer(&self, device_id: &str) -> ProtocolResult<bool> {
        let conn = self.conn.lock().unwrap();
        let updated = conn
            .execute(
                "UPDATE peers SET revoked = 1 WHERE device_id = ?1",
                params![device_id],
            )
            .map_err(|e| ProtocolError {
                code: ErrorCode::LimitExceeded,
                message: format!("sqlite revoke peer error: {}", e),
            })?;
        Ok(updated > 0)
    }

    pub fn get_or_create_server_identity(&self) -> ServerIdentity {
        let conn = self.conn.lock().unwrap();
        let existing: Option<Vec<u8>> = conn
            .query_row(
                "SELECT val FROM server_identity WHERE key = 'private_key'",
                [],
                |r| r.get(0),
            )
            .optional()
            .ok()
            .flatten();

        if let Some(priv_bytes) = existing {
            if priv_bytes.len() == 32 {
                let mut pk = [0u8; 32];
                pk.copy_from_slice(&priv_bytes);
                return ServerIdentity::from_private_key(pk);
            }
        }

        let identity = ServerIdentity::generate();
        let _ = conn.execute(
            "INSERT OR REPLACE INTO server_identity (key, val) VALUES ('private_key', ?1)",
            params![&identity.private_key[..]],
        );
        let _ = conn.execute(
            "INSERT OR REPLACE INTO server_identity (key, val) VALUES ('public_key', ?1)",
            params![&identity.public_key[..]],
        );
        let _ = conn.execute(
            "INSERT OR REPLACE INTO server_identity (key, val) VALUES ('fingerprint', ?1)",
            params![identity.fingerprint.as_bytes()],
        );
        identity
    }

    pub fn get_or_create_server_fingerprint(&self) -> String {
        self.get_or_create_server_identity().fingerprint
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
    active_pairing_session: Arc<Mutex<Option<PairingSession>>>,
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
        if let Ok(peers) = store.ledger().load_peers() {
            for peer in peers {
                registry.enroll(peer);
            }
        }

        Self {
            store,
            registry,
            limiter: RateLimiter::new(5, Duration::from_secs(60)),
            replay_filter: ReplayFilter::new(),
            max_concurrent_transfers,
            active_transfers: Arc::new(Mutex::new(HashSet::new())),
            active_pairing_session: Arc::new(Mutex::new(None)),
        }
    }

    pub fn enroll_peer(&self, peer: PairedPeer) -> ProtocolResult<()> {
        self.store.ledger().save_peer(&peer)?;
        self.registry.enroll(peer);
        Ok(())
    }

    pub fn revoke_peer(&self, device_id: &str) -> bool {
        let _ = self.store.ledger().revoke_peer(device_id);
        self.registry.revoke(device_id)
    }

    pub fn server_identity(&self) -> ServerIdentity {
        self.store.ledger().get_or_create_server_identity()
    }

    pub fn server_fingerprint(&self) -> String {
        self.store.ledger().get_or_create_server_fingerprint()
    }

    pub fn registry(&self) -> &PairedPeerRegistry {
        &self.registry
    }

    pub fn store(&self) -> &DurableFileStore {
        &self.store
    }

    pub fn limiter(&self) -> &RateLimiter {
        &self.limiter
    }

    pub fn start_pairing_session(&self, client_id_hint: Option<String>, ttl_secs: u64) -> PairingSession {
        let session = PairingSession::new(
            client_id_hint.unwrap_or_else(|| "galaxy-watch".to_string()),
            ttl_secs,
        );
        let mut lock = self.active_pairing_session.lock().unwrap();
        *lock = Some(session.clone());
        session
    }

    pub fn set_pairing_pin(&self, pin: &str, ttl_secs: u64) -> PairingSession {
        let mut session = PairingSession::new("galaxy-watch".to_string(), ttl_secs);
        session.pin = pin.to_string();
        let mut lock = self.active_pairing_session.lock().unwrap();
        *lock = Some(session.clone());
        session
    }

    pub fn get_active_pairing_session(&self) -> Option<PairingSession> {
        let mut lock = self.active_pairing_session.lock().unwrap();
        if let Some(session) = lock.as_ref() {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if now > session.expires_at_epoch_s {
                *lock = None;
                return None;
            }
        }
        lock.clone()
    }

    pub fn consume_pairing_session(&self) -> Option<PairingSession> {
        let mut lock = self.active_pairing_session.lock().unwrap();
        lock.take()
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
        if self.store.ledger().get_manifest(&req.transfer_id).is_none() {
            return Err(ProtocolError {
                code: ErrorCode::TransferNotFound,
                message: format!("transfer {} not found in ledger", req.transfer_id),
            });
        }
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

    #[test]
    fn durable_ledger_fails_closed_on_corrupted_database() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("corrupt_ledger.db");
        // Write invalid corrupted binary data
        fs::write(&db_path, b"CORRUPTED_NOT_A_SQLITE_DATABASE_HEADER_DATA_12345678").unwrap();

        // Must fail closed with error, never silently restart empty
        let open_result = DurableTransferLedger::open(&db_path);
        assert!(open_result.is_err(), "Opening corrupted ledger must fail closed");
    }

    #[test]
    fn http_server_handles_network_requests_over_real_tcp() {
        let temp = tempdir().unwrap();
        let ledger = DurableTransferLedger::open(temp.path().join("ledger.db")).unwrap();
        let store = Arc::new(DurableFileStore::new(
            temp.path().join("staging"),
            temp.path().join("dest"),
            ledger,
        ).unwrap());

        let registry = Arc::new(PairedPeerRegistry::new());
        let device_secret = [0x42u8; 32];
        registry.enroll(PairedPeer {
            device_id: "test-watch".to_string(),
            device_name: "Watch Test".to_string(),
            shared_secret: device_secret,
            enrolled_at_epoch_s: 1700000000,
            revoked: false,
        });

        let service = Arc::new(ReceiverService::new(store, registry, 4));
        let server = HttpServer::bind("127.0.0.1:0", service.clone()).unwrap();
        let handle = server.start_background().unwrap();
        let addr = handle.local_addr();

        // 1. Test GET /v1/status over real TCP socket
        {
            let mut stream = std::net::TcpStream::connect(addr).unwrap();
            let req = format!("GET /v1/status HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", addr);
            stream.write_all(req.as_bytes()).unwrap();
            let mut resp = String::new();
            stream.read_to_string(&mut resp).unwrap();
            assert!(resp.starts_with("HTTP/1.1 200 OK"), "Unexpected status response: {}", resp);
            assert!(resp.contains("\"protocol\":\"0.1.0\"") || resp.contains("max_frame_bytes"));
        }

        // 2. Test authenticated POST /v1/transfers over real TCP socket
        {
            let token = AuthToken::create("test-watch", &device_secret);
            let token_json = serde_json::to_string(&token).unwrap();

            let manifest = Manifest::new(
                "transfer-tcp-1".to_string(),
                "audio.m4a".to_string(),
                1024,
                [0xAAu8; 32],
                1700000000,
            ).unwrap();
            let body = serde_json::to_vec(&manifest).unwrap();

            let mut stream = std::net::TcpStream::connect(addr).unwrap();
            let req = format!(
                "POST /v1/transfers HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                addr, token_json, body.len()
            );
            stream.write_all(req.as_bytes()).unwrap();
            stream.write_all(&body).unwrap();

            let mut resp = String::new();
            stream.read_to_string(&mut resp).unwrap();
            assert!(resp.starts_with("HTTP/1.1 201 Created"), "Unexpected create response: {}", resp);
            assert!(resp.contains("transfer-tcp-1"));
        }

        // 3. Test POST /v1/pair and GET /v1/peers over real TCP socket
        {
            service.set_pairing_pin("654321", 300);
            let pair_body = serde_json::to_vec(&serde_json::json!({
                "device_id": "watch-pin-test",
                "device_name": "Galaxy Watch Ultra",
                "pin": "654321"
            })).unwrap();

            let mut stream = std::net::TcpStream::connect(addr).unwrap();
            let req = format!(
                "POST /v1/pair HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                addr, pair_body.len()
            );
            stream.write_all(req.as_bytes()).unwrap();
            stream.write_all(&pair_body).unwrap();
            let mut resp = String::new();
            stream.read_to_string(&mut resp).unwrap();
            assert!(resp.starts_with("HTTP/1.1 200 OK"), "Unexpected pair response: {}", resp);
            assert!(resp.contains("\"status\":\"paired\""));

            // Check GET /v1/peers
            let mut stream2 = std::net::TcpStream::connect(addr).unwrap();
            let req2 = format!("GET /v1/peers HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", addr);
            stream2.write_all(req2.as_bytes()).unwrap();
            let mut resp2 = String::new();
            stream2.read_to_string(&mut resp2).unwrap();
            assert!(resp2.starts_with("HTTP/1.1 200 OK"));
            assert!(resp2.contains("watch-pin-test"));
        }

        handle.stop();
    }
}

