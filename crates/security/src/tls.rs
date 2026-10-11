//! Independently pinned TLS with normal WebPKI and handshake signature verification.
// START_MODULE_CONTRACT
// PURPOSE: Authenticate the receiver certificate before any sensitive network request.
// SCOPE: TLS 1.3, exact out-of-band DER pin, persistent protected local identity, bounded sockets.
// DEPENDS: M-PAIRING-SECURITY, M-WINDOWS-RECEIVER
// LINKS: M-PAIRING-SECURITY, V-M-PAIRING-SECURITY, M-WINDOWS-RECEIVER
// END_MODULE_CONTRACT
// START_MODULE_MAP
//   TlsIdentity - persistent receiver certificate and protected signing key.
//   PinnedVerifier - exact pin followed by WebPKI certificate and signature verification.
//   connect_pinned - connect only to the independently trusted receiver identity.
// END_MODULE_MAP
use crate::{bytes_to_hex, hex_to_32};
use rustls::{client::{danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier}, WebPkiServerVerifier},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
    ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme, StreamOwned};
use sha2::{Digest, Sha256};
use std::{fs::{self, OpenOptions}, io::{self, Write}, net::{TcpStream, ToSocketAddrs}, path::Path, sync::Arc, time::Duration};

pub const SERVICE_NAME: &str = "openwearsync.local";
pub use rustls::{ServerConfig, ServerConnection, StreamOwned as TlsStream};

pub struct TlsIdentity {
    pub certificate: Vec<u8>,
    pub fingerprint: String,
    pub config: Arc<ServerConfig>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct StoredIdentity { certificate: Vec<u8>, protected_key: Vec<u8> }

impl TlsIdentity {
    pub fn load_or_create(root: &Path) -> io::Result<Self> {
        fs::create_dir_all(root)?;
        let lock = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(root.join("tls.identity.lock"))?;
        lock.try_lock().map_err(|e| io::Error::other(e.to_string()))?;
        let path = root.join("tls.identity.v2");
        let stored: StoredIdentity = if path.exists() {
            serde_json::from_slice(&fs::read(&path)?).map_err(io::Error::other)?
        } else {
            let mut params = rcgen::CertificateParams::new(vec![SERVICE_NAME.into(), "localhost".into(), "127.0.0.1".into()]).map_err(io::Error::other)?;
            let now = time::OffsetDateTime::now_utc();
            params.not_before = now - time::Duration::minutes(5);
            params.not_after = now + time::Duration::days(3650);
            params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
            params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
            let key = rcgen::KeyPair::generate().map_err(io::Error::other)?;
            let cert = params.self_signed(&key).map_err(io::Error::other)?;
            let stored = StoredIdentity { certificate: cert.der().to_vec(), protected_key: protect_key(&key.serialize_der())? };
            let bytes = serde_json::to_vec(&stored).map_err(io::Error::other)?;
            let tmp = root.join("tls.identity.v2.new");
            let mut options = OpenOptions::new();
            options.write(true).create(true).truncate(true);
            #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
            let mut file = options.open(&tmp)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::rename(tmp, &path)?;
            stored
        };
        let key = unprotect_key(&stored.protected_key)?;
        let config = ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13]).map_err(io::Error::other)?
            .with_no_client_auth().with_single_cert(vec![CertificateDer::from(stored.certificate.clone())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key))).map_err(io::Error::other)?;
        // Public trust material for the local desktop controller, derived from the validated identity.
        fs::write(root.join("receiver-cert.der"), &stored.certificate)?;
        let fingerprint = bytes_to_hex(&Sha256::digest(&stored.certificate));
        Ok(Self { certificate: stored.certificate, fingerprint, config: Arc::new(config) })
    }
}

#[cfg(windows)]
fn dpapi(bytes: &[u8], encrypt: bool) -> io::Result<Vec<u8>> {
    use windows_sys::Win32::{Foundation::LocalFree, Security::Cryptography::{CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN}};
    let input = CRYPT_INTEGER_BLOB { cbData: u32::try_from(bytes.len()).map_err(io::Error::other)?, pbData: bytes.as_ptr() as *mut u8 };
    let mut output = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
    let ok = unsafe { if encrypt {
        CryptProtectData(&input, std::ptr::null(), std::ptr::null(), std::ptr::null_mut(), std::ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut output)
    } else {
        CryptUnprotectData(&input, std::ptr::null_mut(), std::ptr::null(), std::ptr::null_mut(), std::ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut output)
    }};
    if ok == 0 { return Err(io::Error::last_os_error()); }
    let result = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe { LocalFree(output.pbData as *mut _); }
    Ok(result)
}
#[cfg(windows)] fn protect_key(bytes: &[u8]) -> io::Result<Vec<u8>> { dpapi(bytes, true) }
#[cfg(windows)] fn unprotect_key(bytes: &[u8]) -> io::Result<Vec<u8>> { dpapi(bytes, false) }
#[cfg(not(windows))] fn protect_key(bytes: &[u8]) -> io::Result<Vec<u8>> { Ok(bytes.to_vec()) }
#[cfg(not(windows))] fn unprotect_key(bytes: &[u8]) -> io::Result<Vec<u8>> { Ok(bytes.to_vec()) }

#[derive(Debug)]
pub struct PinnedVerifier { pin: [u8; 32] }
impl PinnedVerifier {
    pub fn new(pin: &str) -> io::Result<Self> {
        Ok(Self { pin: hex_to_32(pin).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "An independent full certificate SHA-256 pin is required"))? })
    }
    fn webpki(&self, cert: &CertificateDer<'_>) -> Result<Arc<WebPkiServerVerifier>, rustls::Error> {
        if Sha256::digest(cert.as_ref()).as_slice() != self.pin { return Err(rustls::Error::General("Receiver certificate pin mismatch".into())); }
        let mut roots = RootCertStore::empty();
        roots.add(cert.clone().into_owned())?;
        WebPkiServerVerifier::builder_with_provider(Arc::new(roots), Arc::new(rustls::crypto::ring::default_provider()))
            .build().map_err(|e| rustls::Error::General(e.to_string()))
    }
}
impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(&self, cert: &CertificateDer<'_>, intermediates: &[CertificateDer<'_>], name: &ServerName<'_>, ocsp: &[u8], now: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
        self.webpki(cert)?.verify_server_cert(cert, intermediates, name, ocsp, now)
    }
    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, signature: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.webpki(cert)?.verify_tls12_signature(message, cert, signature)
    }
    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, signature: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.webpki(cert)?.verify_tls13_signature(message, cert, signature)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> { rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes() }
}

pub fn connect_pinned(host: &str, port: u16, pin: &str, timeout: Duration) -> io::Result<StreamOwned<ClientConnection, TcpStream>> {
    let verifier = Arc::new(PinnedVerifier::new(pin)?);
    let config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13]).map_err(io::Error::other)?
        .dangerous().with_custom_certificate_verifier(verifier).with_no_client_auth();
    let mut stream = None;
    for addr in (host, port).to_socket_addrs()? { if let Ok(s) = TcpStream::connect_timeout(&addr, timeout) { stream = Some(s); break; } }
    let socket = stream.ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "Receiver unavailable"))?;
    socket.set_read_timeout(Some(timeout))?;
    socket.set_write_timeout(Some(timeout))?;
    let conn = ClientConnection::new(Arc::new(config), ServerName::try_from(SERVICE_NAME).map_err(io::Error::other)?).map_err(io::Error::other)?;
    let mut tls = StreamOwned::new(conn, socket);
    // Complete authentication before the caller can write a PIN, token, metadata or audio.
    while tls.conn.is_handshaking() { tls.conn.complete_io(&mut tls.sock)?; }
    Ok(tls)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn certificate(name: &str, expired: bool, usage: rcgen::ExtendedKeyUsagePurpose) -> Vec<u8> {
        let mut params = rcgen::CertificateParams::new(vec![name.into()]).unwrap();
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::days(2);
        params.not_after = now + time::Duration::days(if expired { -1 } else { 1 });
        params.extended_key_usages = vec![usage];
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        params.self_signed(&rcgen::KeyPair::generate().unwrap()).unwrap().der().to_vec()
    }
    fn verify(bytes: Vec<u8>) -> Result<ServerCertVerified, rustls::Error> {
        let pin = bytes_to_hex(&Sha256::digest(&bytes));
        PinnedVerifier::new(&pin).unwrap().verify_server_cert(&CertificateDer::from(bytes), &[],
            &ServerName::try_from(SERVICE_NAME).unwrap(), &[], UnixTime::now())
    }
    #[test]
    fn exact_pin_does_not_bypass_service_name_validity_or_usage() {
        assert!(verify(certificate(SERVICE_NAME, false, rcgen::ExtendedKeyUsagePurpose::ServerAuth)).is_ok());
        assert!(verify(certificate("impostor.local", false, rcgen::ExtendedKeyUsagePurpose::ServerAuth)).is_err());
        assert!(verify(certificate(SERVICE_NAME, true, rcgen::ExtendedKeyUsagePurpose::ServerAuth)).is_err());
        assert!(verify(certificate(SERVICE_NAME, false, rcgen::ExtendedKeyUsagePurpose::ClientAuth)).is_err());
    }
    #[test]
    fn missing_wrong_and_non_ascii_pins_are_rejected() {
        assert!(PinnedVerifier::new("").is_err());
        assert!(PinnedVerifier::new(&"а".repeat(32)).is_err());
        let bytes = certificate(SERVICE_NAME, false, rcgen::ExtendedKeyUsagePurpose::ServerAuth);
        assert!(PinnedVerifier::new(&"00".repeat(32)).unwrap().verify_server_cert(&CertificateDer::from(bytes), &[],
            &ServerName::try_from(SERVICE_NAME).unwrap(), &[], UnixTime::now()).is_err());
    }
    #[test]
    fn protected_identity_survives_restart_but_corruption_never_rotates_it() {
        let root = tempfile::tempdir().unwrap();
        let first = TlsIdentity::load_or_create(root.path()).unwrap();
        assert_eq!(first.fingerprint, TlsIdentity::load_or_create(root.path()).unwrap().fingerprint);
        let path = root.path().join("tls.identity.v2");
        let mut stored: StoredIdentity = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        stored.protected_key.fill(0);
        let corrupt = serde_json::to_vec(&stored).unwrap();
        fs::write(&path, &corrupt).unwrap();
        assert!(TlsIdentity::load_or_create(root.path()).is_err());
        assert_eq!(corrupt, fs::read(&path).unwrap());
        assert_eq!(first.certificate, fs::read(root.path().join("receiver-cert.der")).unwrap());
    }
    #[test]
    fn protected_key_round_trips_without_plaintext_storage_on_windows() {
        let key = rcgen::KeyPair::generate().unwrap().serialize_der();
        let protected = protect_key(&key).unwrap();
        assert_eq!(key, unprotect_key(&protected).unwrap());
        #[cfg(windows)] assert_ne!(key, protected);
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            let root = tempfile::tempdir().unwrap();
            TlsIdentity::load_or_create(root.path()).unwrap();
            assert_eq!(fs::metadata(root.path().join("tls.identity.v2")).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }
}
