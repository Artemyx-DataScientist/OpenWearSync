//! Loopback-only fixture for actual JVM/JNI client integration; excluded from normal builds.
// START_MODULE_CONTRACT
// PURPOSE: Run a real receiver with a test-only enrolled peer in isolated temporary storage.
// SCOPE: Explicit integration-harness feature, loopback sockets and caller-provided fixture data.
// DEPENDS: M-WINDOWS-RECEIVER, M-PAIRING-SECURITY
// LINKS: M-WINDOWS-RECEIVER, V-M-WINDOWS-RECEIVER, M-PAIRING-SECURITY
// END_MODULE_CONTRACT
// START_MODULE_MAP
//   main - start the loopback fixture and print readiness for the JVM test.
// END_MODULE_MAP
use openwearsync_receiver::{DurableFileStore, DurableTransferLedger, HttpServer, ReceiverService};
use openwearsync_security::{PairedPeer, PairedPeerRegistry};
use std::{path::PathBuf, sync::Arc};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(std::env::var("OPENWEARSYNC_FIXTURE_DATA")?);
    let store = Arc::new(DurableFileStore::new(root.join("staging"), root.join("recordings"),
        DurableTransferLedger::open(root.join("ledger.db"))?)?);
    let service = Arc::new(ReceiverService::new(store, Arc::new(PairedPeerRegistry::new()), 4));
    service.enroll_peer(PairedPeer { device_id: "watch-fixture".into(), device_name: "Fixture".into(),
        shared_secret: [42; 32], enrolled_at_epoch_s: 0, revoked: false })?;
    service.set_pairing_pin("741258", 300);
    let server = HttpServer::bind("127.0.0.1:0", service.clone())?;
    println!("READY {} {}", server.local_addr()?.port(), service.server_fingerprint());
    server.run()?;
    Ok(())
}
