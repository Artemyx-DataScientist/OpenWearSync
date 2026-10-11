// START_MODULE_CONTRACT
// PURPOSE: Prove the receiver never accepts plaintext HTTP on its transfer port.
// SCOPE: Actual loopback listener transport boundary, no hardware claims.
// DEPENDS: M-WINDOWS-RECEIVER, M-PAIRING-SECURITY
// LINKS: M-WINDOWS-RECEIVER, M-PAIRING-SECURITY, V-M-WINDOWS-RECEIVER
// END_MODULE_CONTRACT
// START_MODULE_MAP
//   receiver_rejects_plaintext_status - regression for the HTTPS transport requirement.
// END_MODULE_MAP
use openwearsync_receiver::{DurableFileStore, DurableTransferLedger, HttpServer, ReceiverService};
use openwearsync_security::PairedPeerRegistry;
use std::{io::{Read, Write}, net::TcpStream, sync::Arc, time::Duration};

#[test]
fn receiver_rejects_plaintext_status() {
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(DurableFileStore::new(root.path().join("staging"), root.path().join("recordings"),
        DurableTransferLedger::open(root.path().join("ledger.db")).unwrap()).unwrap());
    let service = Arc::new(ReceiverService::new(store, Arc::new(PairedPeerRegistry::new()), 4));
    let server = HttpServer::bind("127.0.0.1:0", service).unwrap().start_background().unwrap();
    let mut socket = TcpStream::connect(server.local_addr()).unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    socket.write_all(b"GET /v1/status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();
    let mut bytes = [0; 1024];
    let n = socket.read(&mut bytes).unwrap_or(0);
    server.stop();
    assert!(!bytes[..n].starts_with(b"HTTP/1.1 200"), "Receiver currently exposes unencrypted HTTP status");
}
