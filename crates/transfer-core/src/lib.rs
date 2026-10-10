//! Streaming sender and receiver transfer reconciliation state machine.

use openwearsync_protocol::{
    ChunkDescriptor, ChunkOutcome, CommitRequest, CreateTransferRequest, ErrorCode, Manifest,
    ProtocolError, ProtocolResult, ReconcileRequest, Request, Response, UploadChunkRequest,
    MAX_CHUNK_BYTES,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    io::{self, Read},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

// START_MODULE_CONTRACT
// PURPOSE: Streaming sender and receiver transfer reconciliation state machine.
// SCOPE: Session state, chunk generation, offset reconciliation, cancellation tokens, integrity checking.
// DEPENDS: openwearsync-protocol, sha2
// LINKS: M-TRANSFER-CORE, M-WINDOWS-RECEIVER, V-M-TRANSFER-CORE, DF-RECORDING-MANIFEST, DF-ENCRYPTED-CHUNK-UPLOAD, DF-DURABLE-CHECKPOINT
// END_MODULE_CONTRACT

// START_MODULE_MAP
//   CancellationToken - cooperative thread-safe cancellation signal crossing FFI boundaries.
//   StreamingChunkReader - stream reader yielding bounded chunks with incremental digests without buffering full file.
//   TransferReconciliation - tracks acknowledged chunk intervals and determines completeness and resume state.
//   TransferSession - high-level cancellable sender session driving create, reconcile, chunk upload, and commit.
//   MockTransport - in-memory controllable transport for resilience, retry, and reconnect tests.
// END_MODULE_MAP

/// Cooperative cancellation token across threads and FFI boundaries.
#[derive(Debug, Clone, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    pub fn check(&self) -> ProtocolResult<()> {
        if self.is_cancelled() {
            Err(ProtocolError {
                code: ErrorCode::Conflict,
                message: "transfer cancelled by user or energy policy".to_string(),
            })
        } else {
            Ok(())
        }
    }
}

/// Computes SHA-256 of an in-memory buffer.
pub fn hash_sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Single chunk yielded by the streaming reader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamChunk {
    pub descriptor: ChunkDescriptor,
    pub payload: Vec<u8>,
}

/// Reads a stream in bounded chunks while computing running stream digest and chunk digests.
/// Never loads the entire stream into memory.
pub struct StreamingChunkReader<R: Read> {
    reader: R,
    chunk_size: u32,
    current_offset: u64,
    stream_hasher: Sha256,
    finished: bool,
}

impl<R: Read> StreamingChunkReader<R> {
    // START_CONTRACT: StreamingChunkReader::new
    // PURPOSE: Initialize a bounded streaming chunk reader.
    // INPUTS: { reader: R - source byte stream; chunk_size: u32 - bounded chunk size }
    // OUTPUTS: { StreamingChunkReader<R> - initialized reader }
    // SIDE_EFFECTS: none
    // END_CONTRACT: StreamingChunkReader::new
    pub fn new(reader: R, chunk_size: u32) -> Self {
        let chunk_size = chunk_size.clamp(1, MAX_CHUNK_BYTES);
        Self {
            reader,
            chunk_size,
            current_offset: 0,
            stream_hasher: Sha256::new(),
            finished: false,
        }
    }

    // START_CONTRACT: StreamingChunkReader::next_chunk
    // PURPOSE: Read the next bounded chunk and calculate its digest without reading beyond chunk_size.
    // INPUTS: { token: &CancellationToken - cancellation token }
    // OUTPUTS: { io::Result<Option<StreamChunk>> - next chunk or EOF }
    // SIDE_EFFECTS: advances reader position, updates running stream SHA-256.
    // END_CONTRACT: StreamingChunkReader::next_chunk
    pub fn next_chunk(&mut self, token: &CancellationToken) -> io::Result<Option<StreamChunk>> {
        if self.finished {
            return Ok(None);
        }
        if token.is_cancelled() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "streaming cancelled",
            ));
        }

        let mut buffer = vec![0u8; self.chunk_size as usize];
        let mut total_read = 0;

        while total_read < buffer.len() {
            match self.reader.read(&mut buffer[total_read..]) {
                Ok(0) => break,
                Ok(n) => total_read += n,
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }

        if total_read == 0 {
            self.finished = true;
            return Ok(None);
        }

        buffer.truncate(total_read);
        self.stream_hasher.update(&buffer);

        let chunk_sha256 = hash_sha256(&buffer);
        let descriptor = ChunkDescriptor {
            offset: self.current_offset,
            length: total_read as u32,
            sha256: chunk_sha256,
        };

        let chunk = StreamChunk {
            descriptor,
            payload: buffer,
        };

        self.current_offset += total_read as u64;
        Ok(Some(chunk))
    }

    /// Current offset reached so far.
    pub fn current_offset(&self) -> u64 {
        self.current_offset
    }

    /// Final total SHA-256 of the entire stream after reading to EOF.
    pub fn finish_stream_digest(self) -> [u8; 32] {
        self.stream_hasher.finalize().into()
    }
}

/// Half-open byte interval `[start, end)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ByteRange {
    pub start: u64,
    pub end: u64,
}

impl ByteRange {
    pub fn new(start: u64, end: u64) -> Option<Self> {
        if start <= end {
            Some(Self { start, end })
        } else {
            None
        }
    }

    pub fn length(&self) -> u64 {
        self.end - self.start
    }

    pub fn overlaps_or_adjacent(&self, other: &Self) -> bool {
        self.start <= other.end && other.start <= self.end
    }

    pub fn merge(&self, other: &Self) -> Self {
        Self {
            start: self.start.min(other.start),
            end: self.end.max(other.end),
        }
    }
}

/// Tracks acknowledged byte intervals and checks completeness.
#[derive(Debug, Clone, Default)]
pub struct TransferReconciliation {
    ranges: BTreeSet<ByteRange>,
    total_expected_size: u64,
    received_bytes: u64,
}

impl TransferReconciliation {
    // START_CONTRACT: TransferReconciliation::new
    // PURPOSE: Initialize reconciliation tracker for an expected transfer size.
    // INPUTS: { total_expected_size: u64 }
    // OUTPUTS: { TransferReconciliation - initialized state }
    // SIDE_EFFECTS: none
    // END_CONTRACT: TransferReconciliation::new
    pub fn new(total_expected_size: u64) -> Self {
        Self {
            ranges: BTreeSet::new(),
            total_expected_size,
            received_bytes: 0,
        }
    }

    /// Check if a chunk at [offset, offset + length) has already been fully received.
    pub fn is_chunk_received(&self, offset: u64, length: u32) -> bool {
        let chunk_end = match offset.checked_add(u64::from(length)) {
            Some(end) => end,
            None => return false,
        };
        for range in &self.ranges {
            if range.start <= offset && chunk_end <= range.end {
                return true;
            }
        }
        false
    }

    // START_CONTRACT: TransferReconciliation::record_chunk
    // PURPOSE: Record receipt of a chunk, merging contiguous byte intervals.
    // INPUTS: { offset: u64, length: u32 }
    // OUTPUTS: { ChunkOutcome - Accepted if new data was recorded, AlreadyReceived if duplicate }
    // SIDE_EFFECTS: updates acknowledged ranges and received byte counter.
    // END_CONTRACT: TransferReconciliation::record_chunk
    pub fn record_chunk(&mut self, offset: u64, length: u32) -> ChunkOutcome {
        if length == 0 {
            return ChunkOutcome::AlreadyReceived;
        }
        let end = match offset.checked_add(u64::from(length)) {
            Some(e) => e,
            None => return ChunkOutcome::AlreadyReceived,
        };
        if end > self.total_expected_size {
            return ChunkOutcome::AlreadyReceived;
        }

        if self.is_chunk_received(offset, length) {
            return ChunkOutcome::AlreadyReceived;
        }

        let mut new_range = ByteRange { start: offset, end };
        let mut to_remove = Vec::new();

        for r in &self.ranges {
            if new_range.overlaps_or_adjacent(r) {
                new_range = new_range.merge(r);
                to_remove.push(*r);
            }
        }

        for r in to_remove {
            self.ranges.remove(&r);
        }
        self.ranges.insert(new_range);

        // Recompute received bytes from merged intervals
        self.received_bytes = self.ranges.iter().map(ByteRange::length).sum();
        ChunkOutcome::Accepted
    }

    /// True if the ranges continuously span [0, total_expected_size).
    pub fn is_complete(&self) -> bool {
        if self.total_expected_size == 0 {
            return true;
        }
        if self.ranges.len() == 1 {
            let single = self.ranges.iter().next().unwrap();
            single.start == 0 && single.end == self.total_expected_size
        } else {
            false
        }
    }

    pub fn received_bytes(&self) -> u64 {
        self.received_bytes
    }

    pub fn total_expected_size(&self) -> u64 {
        self.total_expected_size
    }

    pub fn progress_fraction(&self) -> f64 {
        if self.total_expected_size == 0 {
            1.0
        } else {
            (self.received_bytes as f64 / self.total_expected_size as f64).clamp(0.0, 1.0)
        }
    }
}

/// Abstract transport trait for sending typed requests and receiving typed responses.
pub trait Transport {
    fn execute(&mut self, request: Request) -> ProtocolResult<Response>;
}

/// Transfer outcome summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferSummary {
    pub transfer_id: String,
    pub total_bytes: u64,
    pub chunks_sent: usize,
    pub chunks_skipped: usize,
    pub final_sha256: [u8; 32],
    pub committed: bool,
}

/// Cancellable sender orchestrator.
pub struct TransferSession<'a, T: Transport> {
    transport: &'a mut T,
    manifest: Manifest,
    token: CancellationToken,
}

impl<'a, T: Transport> TransferSession<'a, T> {
    pub fn new(transport: &'a mut T, manifest: Manifest, token: CancellationToken) -> Self {
        Self {
            transport,
            manifest,
            token,
        }
    }

    // START_CONTRACT: TransferSession::send_stream
    // PURPOSE: Drive creation, reconciliation, bounded chunk upload, and commit for a source stream.
    // INPUTS: { reader: R - source byte stream; on_progress: F - callback reporting (transferred_bytes, total_bytes) }
    // OUTPUTS: { ProtocolResult<TransferSummary> - final verified transfer outcome }
    // SIDE_EFFECTS: sends wire requests, reads from reader, never touches or deletes local source file.
    // END_CONTRACT: TransferSession::send_stream
    pub fn send_stream<R: Read, F: FnMut(u64, u64)>(
        &mut self,
        reader: R,
        mut on_progress: F,
    ) -> ProtocolResult<TransferSummary> {
        self.token.check()?;

        // Step 1: Create or get existing transfer
        let create_req = Request::CreateTransfer(CreateTransferRequest {
            manifest: self.manifest.clone(),
        });

        let transfer_id = match self.transport.execute(create_req) {
            Ok(Response::TransferCreated(res)) => res.transfer_id,
            Ok(Response::Error(err)) if err.code == ErrorCode::Conflict => {
                // Transfer already exists on receiver, reuse ID
                self.manifest.transfer_id.clone()
            }
            Ok(other) => {
                return Err(ProtocolError {
                    code: ErrorCode::InvalidRequest,
                    message: format!("unexpected response to CreateTransfer: {:?}", other),
                });
            }
            Err(e) => return Err(e),
        };

        self.token.check()?;

        // Step 2: Reconcile what receiver already has
        let reconcile_req = Request::ReconcileTransfer(ReconcileRequest {
            transfer_id: transfer_id.clone(),
        });

        let mut reconciliation = TransferReconciliation::new(self.manifest.size_bytes);

        if let Ok(Response::Reconciled(rec)) = self.transport.execute(reconcile_req) {
            for chunk in rec.received {
                reconciliation.record_chunk(chunk.offset, chunk.length);
            }
        }

        on_progress(reconciliation.received_bytes(), self.manifest.size_bytes);

        // Step 3: Stream chunks
        let mut chunk_reader =
            StreamingChunkReader::new(reader, openwearsync_protocol::MAX_CHUNK_BYTES);
        let mut chunks_sent = 0;
        let mut chunks_skipped = 0;

        loop {
            self.token.check()?;

            let chunk_opt = chunk_reader.next_chunk(&self.token).map_err(|e| {
                if e.kind() == io::ErrorKind::Interrupted {
                    ProtocolError {
                        code: ErrorCode::Conflict,
                        message: "transfer cancelled".to_string(),
                    }
                } else {
                    ProtocolError {
                        code: ErrorCode::InvalidChunk,
                        message: format!("read error: {}", e),
                    }
                }
            })?;

            let chunk = match chunk_opt {
                Some(c) => c,
                None => break,
            };

            // Check if already acknowledged by receiver
            if reconciliation.is_chunk_received(chunk.descriptor.offset, chunk.descriptor.length) {
                chunks_skipped += 1;
                continue;
            }

            // Upload chunk
            let upload_req = Request::UploadChunk(UploadChunkRequest {
                transfer_id: transfer_id.clone(),
                chunk: chunk.descriptor.clone(),
                payload: chunk.payload,
            });

            match self.transport.execute(upload_req)? {
                Response::ChunkAccepted(res) => {
                    reconciliation.record_chunk(res.chunk.offset, res.chunk.length);
                    chunks_sent += 1;
                    on_progress(reconciliation.received_bytes(), self.manifest.size_bytes);
                }
                Response::Error(err) => return Err(err),
                other => {
                    return Err(ProtocolError {
                        code: ErrorCode::InvalidChunk,
                        message: format!("unexpected response to UploadChunk: {:?}", other),
                    });
                }
            }
        }

        // Verify that the whole file was read and digest matches manifest
        let actual_digest = chunk_reader.finish_stream_digest();
        if actual_digest != self.manifest.sha256 {
            return Err(ProtocolError {
                code: ErrorCode::InvalidManifest,
                message: "source content hash does not match manifest".to_string(),
            });
        }

        self.token.check()?;

        // Step 4: Commit transfer
        let commit_req = Request::CommitTransfer(CommitRequest {
            transfer_id: transfer_id.clone(),
        });

        match self.transport.execute(commit_req)? {
            Response::Committed(res) => {
                if res.sha256 != self.manifest.sha256 || res.size_bytes != self.manifest.size_bytes
                {
                    return Err(ProtocolError {
                        code: ErrorCode::InvalidManifest,
                        message: "receiver committed file integrity mismatch".to_string(),
                    });
                }

                Ok(TransferSummary {
                    transfer_id,
                    total_bytes: self.manifest.size_bytes,
                    chunks_sent,
                    chunks_skipped,
                    final_sha256: res.sha256,
                    committed: true,
                })
            }
            Response::Error(err) => Err(err),
            other => Err(ProtocolError {
                code: ErrorCode::InvalidRequest,
                message: format!("unexpected response to CommitTransfer: {:?}", other),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openwearsync_protocol::{
        ChunkAcceptedResponse, CommittedResponse, ReconciledResponse,
    };
    use std::collections::HashMap;

    /// Mock in-memory receiver transport for deterministic tests.
    struct MockTransport {
        transfers: HashMap<String, Manifest>,
        chunks: HashMap<String, Vec<ChunkDescriptor>>,
        committed: HashMap<String, CommittedResponse>,
        pub drop_next_chunk: bool,
    }

    impl MockTransport {
        fn new() -> Self {
            Self {
                transfers: HashMap::new(),
                chunks: HashMap::new(),
                committed: HashMap::new(),
                drop_next_chunk: false,
            }
        }
    }

    impl Transport for MockTransport {
        fn execute(&mut self, request: Request) -> ProtocolResult<Response> {
            match request {
                Request::Status(_) => Ok(Response::Status(openwearsync_protocol::StatusResponse {
                    protocol: openwearsync_protocol::ProtocolVersion::CURRENT,
                    capabilities: openwearsync_protocol::Capabilities::new(
                        openwearsync_protocol::MAX_FRAME_BYTES,
                        openwearsync_protocol::MAX_CHUNK_BYTES,
                    )?,
                })),
                Request::CreateTransfer(req) => {
                    if self.transfers.contains_key(&req.manifest.transfer_id) {
                        return Ok(Response::Error(ProtocolError {
                            code: ErrorCode::Conflict,
                            message: "already exists".to_string(),
                        }));
                    }
                    let id = req.manifest.transfer_id.clone();
                    self.transfers.insert(id.clone(), req.manifest);
                    self.chunks.insert(id.clone(), Vec::new());
                    Ok(Response::TransferCreated(
                        openwearsync_protocol::TransferCreatedResponse { transfer_id: id },
                    ))
                }
                Request::ReconcileTransfer(req) => {
                    let received = self.chunks.get(&req.transfer_id).cloned().unwrap_or_default();
                    Ok(Response::Reconciled(ReconciledResponse {
                        transfer_id: req.transfer_id,
                        received,
                    }))
                }
                Request::UploadChunk(req) => {
                    if self.drop_next_chunk {
                        self.drop_next_chunk = false;
                        return Err(ProtocolError {
                            code: ErrorCode::Conflict,
                            message: "simulated connection drop".to_string(),
                        });
                    }
                    let list = self.chunks.entry(req.transfer_id.clone()).or_default();
                    if list.iter().any(|c| c.offset == req.chunk.offset) {
                        return Ok(Response::ChunkAccepted(ChunkAcceptedResponse {
                            transfer_id: req.transfer_id,
                            chunk: req.chunk,
                            outcome: ChunkOutcome::AlreadyReceived,
                        }));
                    }
                    list.push(req.chunk.clone());
                    Ok(Response::ChunkAccepted(ChunkAcceptedResponse {
                        transfer_id: req.transfer_id,
                        chunk: req.chunk,
                        outcome: ChunkOutcome::Accepted,
                    }))
                }
                Request::CommitTransfer(req) => {
                    let manifest = self.transfers.get(&req.transfer_id).ok_or_else(|| {
                        ProtocolError {
                            code: ErrorCode::TransferNotFound,
                            message: "transfer not found".to_string(),
                        }
                    })?;
                    let committed = CommittedResponse {
                        transfer_id: req.transfer_id.clone(),
                        size_bytes: manifest.size_bytes,
                        sha256: manifest.sha256,
                    };
                    self.committed.insert(req.transfer_id, committed.clone());
                    Ok(Response::Committed(committed))
                }
            }
        }
    }

    #[test]
    fn streaming_chunk_reader_splits_data_and_computes_incremental_digest() {
        let payload = vec![0x42u8; 150_000]; // ~150KB, exceeds 64KB max chunk
        let expected_sha256 = hash_sha256(&payload);

        let token = CancellationToken::new();
        let mut reader = StreamingChunkReader::new(&payload[..], 64 * 1024);

        let chunk1 = reader.next_chunk(&token).unwrap().unwrap();
        assert_eq!(chunk1.descriptor.offset, 0);
        assert_eq!(chunk1.descriptor.length, 64 * 1024);
        assert_eq!(chunk1.descriptor.sha256, hash_sha256(&chunk1.payload));

        let chunk2 = reader.next_chunk(&token).unwrap().unwrap();
        assert_eq!(chunk2.descriptor.offset, 64 * 1024);
        assert_eq!(chunk2.descriptor.length, 64 * 1024);

        let chunk3 = reader.next_chunk(&token).unwrap().unwrap();
        assert_eq!(chunk3.descriptor.offset, 128 * 1024);
        assert_eq!(chunk3.descriptor.length, 150_000 - 128 * 1024);

        assert!(reader.next_chunk(&token).unwrap().is_none());
        assert_eq!(reader.finish_stream_digest(), expected_sha256);
    }

    #[test]
    fn transfer_reconciliation_merges_contiguous_intervals_and_detects_completeness() {
        let mut rec = TransferReconciliation::new(100);
        assert_eq!(rec.record_chunk(0, 40), ChunkOutcome::Accepted);
        assert!(!rec.is_complete());
        assert_eq!(rec.received_bytes(), 40);

        // Duplicate chunk
        assert_eq!(rec.record_chunk(0, 40), ChunkOutcome::AlreadyReceived);

        // Non-contiguous chunk
        assert_eq!(rec.record_chunk(60, 40), ChunkOutcome::Accepted);
        assert!(!rec.is_complete());
        assert_eq!(rec.received_bytes(), 80);

        // Filling the gap [40, 60)
        assert_eq!(rec.record_chunk(40, 20), ChunkOutcome::Accepted);
        assert!(rec.is_complete());
        assert_eq!(rec.received_bytes(), 100);
        assert_eq!(rec.progress_fraction(), 1.0);
    }

    #[test]
    fn full_transfer_session_completes_successfully() {
        let payload = b"Voice recording test payload exceeding small frames - 0123456789".repeat(1000);
        let sha256 = hash_sha256(&payload);
        let manifest = Manifest::new(
            "transfer-test-1".to_string(),
            "recording_001.m4a".to_string(),
            payload.len() as u64,
            sha256,
            1700000000,
        )
        .unwrap();

        let mut transport = MockTransport::new();
        let token = CancellationToken::new();
        let mut session = TransferSession::new(&mut transport, manifest, token);

        let mut progress_reports = Vec::new();
        let summary = session
            .send_stream(&payload[..], |transferred, total| {
                progress_reports.push((transferred, total));
            })
            .unwrap();

        assert_eq!(summary.transfer_id, "transfer-test-1");
        assert_eq!(summary.total_bytes, payload.len() as u64);
        assert!(summary.committed);
        assert!(summary.chunks_sent > 0);
        assert_eq!(summary.chunks_skipped, 0);
        assert!(!progress_reports.is_empty());
        assert_eq!(progress_reports.last().unwrap().0, payload.len() as u64);
    }

    #[test]
    fn transfer_session_resumes_interrupted_transfer_without_resending_received_chunks() {
        let payload = vec![0x77u8; 128 * 1024];
        let sha256 = hash_sha256(&payload);
        let manifest = Manifest::new(
            "transfer-resume-1".to_string(),
            "voice.m4a".to_string(),
            payload.len() as u64,
            sha256,
            1700000000,
        )
        .unwrap();

        let mut transport = MockTransport::new();
        // Simulate that the receiver already has the first chunk [0, 64KB)
        transport.transfers.insert(manifest.transfer_id.clone(), manifest.clone());
        transport.chunks.insert(
            manifest.transfer_id.clone(),
            vec![ChunkDescriptor {
                offset: 0,
                length: 64 * 1024,
                sha256: hash_sha256(&payload[..64 * 1024]),
            }],
        );

        let token = CancellationToken::new();
        let mut session = TransferSession::new(&mut transport, manifest, token);

        let summary = session.send_stream(&payload[..], |_, _| {}).unwrap();
        assert_eq!(summary.chunks_skipped, 1);
        assert_eq!(summary.chunks_sent, 1);
        assert!(summary.committed);
    }

    #[test]
    fn transfer_session_aborts_promptly_on_cancellation() {
        let payload = vec![0xAAu8; 256 * 1024];
        let sha256 = hash_sha256(&payload);
        let manifest = Manifest::new(
            "transfer-cancel-1".to_string(),
            "cancelled.m4a".to_string(),
            payload.len() as u64,
            sha256,
            1700000000,
        )
        .unwrap();

        let mut transport = MockTransport::new();
        let token = CancellationToken::new();
        token.cancel(); // Pre-cancelled

        let mut session = TransferSession::new(&mut transport, manifest, token);
        let result = session.send_stream(&payload[..], |_, _| {});

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ErrorCode::Conflict);
    }

    #[test]
    fn transfer_session_fails_if_source_content_checksum_mismatches_manifest() {
        let payload = vec![0x11u8; 1024];
        let wrong_sha256 = [0xFFu8; 32];
        let manifest = Manifest::new(
            "transfer-mismatch-1".to_string(),
            "bad.m4a".to_string(),
            payload.len() as u64,
            wrong_sha256,
            1700000000,
        )
        .unwrap();

        let mut transport = MockTransport::new();
        let token = CancellationToken::new();
        let mut session = TransferSession::new(&mut transport, manifest, token);

        let result = session.send_stream(&payload[..], |_, _| {});
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ErrorCode::InvalidManifest);
    }
}
