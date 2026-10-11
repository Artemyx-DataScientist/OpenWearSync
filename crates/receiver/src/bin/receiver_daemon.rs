//! Windows receiver daemon executable binding local LAN TCP/HTTP listener.

use openwearsync_receiver::{DurableFileStore, DurableTransferLedger, HttpServer, ReceiverService};
use openwearsync_security::PairedPeerRegistry;
use std::{env, fs, path::PathBuf, sync::Arc};

// START_MODULE_CONTRACT
// PURPOSE: Standalone Windows daemon binary executing the OpenWearSync HTTP receiver.
// SCOPE: Daemon entrypoint, command-line execution, port binding, and service lifecycle.
// DEPENDS: openwearsync-receiver, openwearsync-security
// LINKS: M-WINDOWS-RECEIVER, V-M-WINDOWS-RECEIVER
// END_MODULE_CONTRACT

// START_MODULE_MAP
//   main - entrypoint initializing storage, SQLite ledger, and binding HTTP server listener.
// END_MODULE_MAP

fn get_data_dir() -> PathBuf {
    if let Ok(appdata) = env::var("APPDATA") {
        PathBuf::from(appdata).join("OpenWearSync")
    } else {
        PathBuf::from("openwearsync-data")
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let data_dir = get_data_dir();
    fs::create_dir_all(&data_dir)?;

    let staging_dir = data_dir.join("staging");
    let dest_dir = data_dir.join("recordings");
    let ledger_path = data_dir.join("ledger.db");

    println!("OpenWearSync Receiver Daemon v0.1.0");
    println!("Data directory: {}", data_dir.display());

    let ledger = DurableTransferLedger::open(&ledger_path)?;
    let store = Arc::new(DurableFileStore::new(staging_dir, dest_dir, ledger)?);
    let registry = Arc::new(PairedPeerRegistry::new());
    let service = Arc::new(ReceiverService::try_new(store, registry, 4)?);

    let port = env::var("OPENWEARSYNC_PORT").unwrap_or_else(|_| "35659".to_string());
    let bind_addr = format!("0.0.0.0:{}", port);

    let session = service.start_pairing_session(None, 300);
    println!("Certificate SHA-256 (enter on watch before PIN): {}", service.server_fingerprint());
    println!("Initial one-use pairing session active for 5 min. PIN: {}", session.pin);

    let server = HttpServer::bind(&bind_addr, service)?;
    println!("Listening for incoming Galaxy Watch transfers on https://{}", bind_addr);
    println!("Press Ctrl+C to terminate.");

    server.run()?;
    Ok(())
}
