// START_MODULE_CONTRACT
// PURPOSE: Full end-to-end simulation of authenticated Wear-to-Windows transfer under simulated connection drops.
// SCOPE: Integrated test connecting TransferSession to ReceiverService with persistent staging and atomic publication.
// DEPENDS: openwearsync-protocol, openwearsync-security, openwearsync-transfer-core, openwearsync-receiver
// LINKS: M-TRANSFER-CORE, M-WINDOWS-RECEIVER, V-M-WINDOWS-RECEIVER, DF-ENCRYPTED-CHUNK-UPLOAD, DF-DURABLE-CHECKPOINT
// END_MODULE_CONTRACT

use openwearsync_protocol::{Manifest, ProtocolError, ProtocolResult, Request, Response};
use openwearsync_receiver::{DurableFileStore, DurableTransferLedger, ReceiverService};
use openwearsync_security::{AuthToken, PairedPeer, PairedPeerRegistry};
use openwearsync_transfer_core::{hash_sha256, CancellationToken, TransferSession, Transport};
use std::{fs, sync::Arc};
use tempfile::tempdir;

struct SimulatedNetworkTransport {
    service: Arc<ReceiverService>,
    device_id: String,
    device_secret: [u8; 32],
    drop_after_chunk_count: Option<usize>,
    chunks_seen: usize,
}

impl Transport for SimulatedNetworkTransport {
    fn execute(&mut self, request: Request) -> ProtocolResult<Response> {
        if let Request::UploadChunk(_) = request {
            self.chunks_seen += 1;
            if let Some(drop_at) = self.drop_after_chunk_count {
                if self.chunks_seen >= drop_at {
                    self.drop_after_chunk_count = None; // Reset so next reconnect works
                    return Err(ProtocolError {
                        code: openwearsync_protocol::ErrorCode::Conflict,
                        message: "simulated Wi-Fi disconnect during chunk upload".to_string(),
                    });
                }
            }
        }
        let token = AuthToken::create(&self.device_id, &self.device_secret);
        self.service.handle_request(request, Some(&token))
    }
}

#[test]
fn simulated_end_to_end_transfer_recovers_after_network_failure() {
    let temp = tempdir().unwrap();
    let ledger_path = temp.path().join("ledger.json");
    let staging_dir = temp.path().join("staging");
    let dest_dir = temp.path().join("recordings");

    let ledger = DurableTransferLedger::open(&ledger_path).unwrap();
    let store = Arc::new(DurableFileStore::new(staging_dir, dest_dir.clone(), ledger).unwrap());

    let registry = Arc::new(PairedPeerRegistry::new());
    let device_secret = [0x7A; 32];
    registry.enroll(PairedPeer {
        device_id: "galaxy-watch-sim".to_string(),
        device_name: "Galaxy Watch 7".to_string(),
        shared_secret: device_secret,
        enrolled_at_epoch_s: 1700000000,
        revoked: false,
    });

    let service = Arc::new(ReceiverService::new(store, registry, 4));

    // Generate 200KB simulated voice recording (> 64KB max chunk)
    let audio_payload = vec![0xEFu8; 200_000];
    let audio_sha256 = hash_sha256(&audio_payload);
    let manifest = Manifest::new(
        "transfer-e2e-sim-1".to_string(),
        "Voice_20261011_001.m4a".to_string(),
        audio_payload.len() as u64,
        audio_sha256,
        1700000000,
    )
    .unwrap();

    // Pass 1: Upload begins, chunk 1 accepted, then drops on chunk 2
    let mut transport1 = SimulatedNetworkTransport {
        service: service.clone(),
        device_id: "galaxy-watch-sim".to_string(),
        device_secret,
        drop_after_chunk_count: Some(2),
        chunks_seen: 0,
    };

    let cancel_token1 = CancellationToken::new();
    let mut session1 = TransferSession::new(&mut transport1, manifest.clone(), cancel_token1);
    let result1 = session1.send_stream(&audio_payload[..], |_, _| {});
    assert!(result1.is_err(), "Expected simulated failure on pass 1");

    // Pass 2: Reconnect with fresh auth token, resumes without re-sending chunk 1
    let mut transport2 = SimulatedNetworkTransport {
        service: service.clone(),
        device_id: "galaxy-watch-sim".to_string(),
        device_secret,
        drop_after_chunk_count: None, // Reliable connection
        chunks_seen: 0,
    };

    let cancel_token2 = CancellationToken::new();
    let mut session2 = TransferSession::new(&mut transport2, manifest, cancel_token2);
    let summary = session2
        .send_stream(&audio_payload[..], |transferred, total| {
            assert!(transferred <= total);
        })
        .expect("Transfer should resume and complete successfully on pass 2");

    assert_eq!(summary.transfer_id, "transfer-e2e-sim-1");
    assert_eq!(summary.total_bytes, 200_000);
    assert!(summary.committed);
    assert_eq!(summary.chunks_skipped, 1, "Should skip chunk 1 already stored in pass 1");
    assert!(summary.chunks_sent >= 2, "Should upload remaining chunks in pass 2");

    // Verify published file in destination directory
    let final_file = dest_dir.join("Voice_20261011_001.m4a");
    assert!(final_file.exists(), "Final file must be published in destination directory");
    let committed_bytes = fs::read(&final_file).unwrap();
    assert_eq!(committed_bytes.len(), 200_000);
    assert_eq!(hash_sha256(&committed_bytes), audio_sha256);
}
