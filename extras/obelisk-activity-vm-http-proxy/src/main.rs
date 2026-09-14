use anyhow::{Context, Result, bail};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use rustls::{
    ServerConfig, ServerConnection, StreamOwned,
    crypto::ring::sign::any_supported_type,
    pki_types::PrivatePkcs8KeyDer,
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    env, fs,
    io::{Read, Write},
    os::unix::net::UnixListener,
    path::{Path, PathBuf},
    process,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

const MAX_HEADER: usize = 64 * 1024;
const MAX_BODY: usize = 1024 * 1024;
static NEXT_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Serialize)]
struct BridgeRequest {
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

#[derive(Deserialize)]
struct BridgeResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body_prefix: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct BridgeDone {
    body_length: usize,
    chunks: usize,
    error: Option<String>,
}

fn main() -> Result<()> {
    let mut args = env::args().skip(1);
    let queue = PathBuf::from(
        args.next()
            .context("usage: obelisk-activity-vm-http-proxy QUEUE_DIR")?,
    );
    let allowed = args
        .next()
        .context("usage: obelisk-activity-vm-http-proxy QUEUE_DIR ALLOWED_HOSTS")?;
    fs::create_dir_all(&queue)?;
    let tls = tls_config(&allowed)?;
    let http_queue = queue.clone();
    thread::spawn(move || listen_http(&http_queue));
    listen_https(&queue, &tls)
}

fn listen_http(queue: &Path) {
    let socket = Path::new("/tmp/obelisk-activity-vm-http.sock");
    let _ = fs::remove_file(socket);
    let listener = UnixListener::bind(socket).expect("binding HTTP bridge socket");
    eprintln!(
        "obelisk-activity-vm HTTP bridge listening on {}",
        socket.display()
    );
    for connection in listener.incoming() {
        match connection {
            Ok(stream) => {
                let queue = queue.to_owned();
                thread::spawn(move || {
                    if let Err(error) = serve(stream, &queue, "http") {
                        eprintln!("obelisk-activity-vm HTTP proxy: {error:#}");
                    }
                });
            }
            Err(error) => eprintln!("obelisk-activity-vm HTTP proxy accept: {error}"),
        }
    }
}

fn listen_https(queue: &Path, config: &Arc<ServerConfig>) -> Result<()> {
    let socket = Path::new("/tmp/obelisk-activity-vm-https.sock");
    let _ = fs::remove_file(socket);
    let listener = UnixListener::bind(socket)?;
    eprintln!(
        "obelisk-activity-vm HTTPS bridge listening on {}",
        socket.display()
    );
    for connection in listener.incoming() {
        let stream = connection?;
        let queue = queue.to_owned();
        let config = config.clone();
        thread::spawn(move || {
            let result = ServerConnection::new(config)
                .map(|session| StreamOwned::new(session, stream))
                .map_err(anyhow::Error::from)
                .and_then(|stream| serve(stream, &queue, "https"));
            if let Err(error) = result {
                eprintln!("obelisk-activity-vm HTTPS proxy: {error:#}");
            }
        });
    }
    Ok(())
}

fn tls_config(allowed: &str) -> Result<Arc<ServerConfig>> {
    let key = KeyPair::generate()?;
    let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "obelisk-activity-vm guest-local CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let ca = CertifiedIssuer::self_signed(ca_params, key)?;
    fs::write("/tmp/obelisk-activity-vm-ca.pem", ca.pem())?;
    let resolver = DynamicCertificateResolver {
        allowed: allowed.split(',').map(str::to_owned).collect(),
        ca,
        certificates: Mutex::new(HashMap::new()),
    };
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
    Ok(Arc::new(config))
}

#[derive(Debug)]
struct DynamicCertificateResolver {
    allowed: Vec<String>,
    ca: CertifiedIssuer<'static, KeyPair>,
    certificates: Mutex<HashMap<String, Arc<CertifiedKey>>>,
}

impl ResolvesServerCert for DynamicCertificateResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let name = hello.server_name()?;
        if !self
            .allowed
            .iter()
            .any(|allowed| allowed == "*" || allowed == name)
        {
            return None;
        }
        let mut certificates = self.certificates.lock().ok()?;
        if let Some(certificate) = certificates.get(name) {
            return Some(certificate.clone());
        }

        let leaf_key = KeyPair::generate().ok()?;
        let mut params = CertificateParams::new(vec![name.to_owned()]).ok()?;
        params
            .distinguished_name
            .push(DnType::CommonName, "obelisk-activity-vm HTTPS bridge");
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let leaf = params.signed_by(&leaf_key, &self.ca).ok()?;
        let private_key = PrivatePkcs8KeyDer::from(leaf_key.serialize_der()).into();
        let signing_key = any_supported_type(&private_key).ok()?;
        let certificate = Arc::new(CertifiedKey::new(vec![leaf.der().clone()], signing_key));
        certificates.insert(name.to_owned(), certificate.clone());
        Some(certificate)
    }
}

fn serve(mut stream: impl Read + Write, queue: &Path, default_scheme: &str) -> Result<()> {
    let mut bytes = Vec::new();
    let header_end = loop {
        if bytes.len() >= MAX_HEADER {
            bail!("request headers exceed {MAX_HEADER} bytes")
        }
        let mut chunk = [0; 4096];
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            bail!("client closed before sending headers")
        }
        bytes.extend_from_slice(&chunk[..read]);
        if let Some(index) = find(&bytes, b"\r\n\r\n") {
            break index + 4;
        }
    };

    let head = std::str::from_utf8(&bytes[..header_end])?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next().context("missing request line")?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().context("missing method")?.to_owned();
    let target = parts.next().context("missing request target")?.to_owned();
    if method.eq_ignore_ascii_case("CONNECT") {
        stream.write_all(b"HTTP/1.1 501 Not Implemented\r\nContent-Length: 42\r\nConnection: close\r\n\r\nHTTPS interception is not implemented yet\n")?;
        return Ok(());
    }

    let mut headers = Vec::new();
    let mut host = None;
    let mut content_length = 0usize;
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').context("malformed request header")?;
        let value = value.trim().to_owned();
        if name.eq_ignore_ascii_case("host") {
            host = Some(value.clone());
        }
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.parse()?;
        }
        headers.push((name.to_owned(), value));
    }
    if content_length > MAX_BODY {
        bail!("request body exceeds {MAX_BODY} bytes")
    }
    while bytes.len() < header_end + content_length {
        let mut chunk = [0; 8192];
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            bail!("client closed before sending request body")
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    let url = if target.starts_with("http://") || target.starts_with("https://") {
        target
    } else {
        format!(
            "{default_scheme}://{}{}",
            host.context("missing Host header")?,
            target
        )
    };
    let request = BridgeRequest {
        method,
        url,
        headers,
        body: bytes[header_end..header_end + content_length].to_vec(),
    };
    let id = format!(
        "{}-{}",
        process::id(),
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    );
    let temporary = queue.join(format!("{id}.tmp"));
    let request_path = queue.join(format!("{id}.request"));
    let response_path = queue.join(format!("{id}.response"));
    fs::write(&temporary, serde_json::to_vec(&request)?)?;
    fs::rename(&temporary, &request_path)?;

    let started = Instant::now();
    while !response_path.exists() {
        if started.elapsed() > Duration::from_secs(60) {
            let _ = fs::remove_file(&request_path);
            bail!("HTTP broker timed out")
        }
        thread::sleep(Duration::from_millis(10));
    }
    let response: BridgeResponse = serde_json::from_slice(&fs::read(&response_path)?)?;
    fs::remove_file(&response_path)?;
    if let Some(error) = response.error {
        let body = format!("request denied or failed: {error}\n");
        write!(
            stream,
            "HTTP/1.1 502 Bad Gateway\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )?;
        return Ok(());
    }
    let body_prefix = response
        .body_prefix
        .context("response has no body prefix")?;
    if !body_prefix
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        bail!("invalid response body prefix")
    }
    write!(
        stream,
        "HTTP/1.1 {} obelisk-activity-vm\r\n",
        response.status
    )?;
    for (name, value) in response.headers {
        if !is_hop_header(&name) && !name.eq_ignore_ascii_case("content-length") {
            write!(stream, "{name}: {value}\r\n")?;
        }
    }
    write!(
        stream,
        "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
    )?;
    stream_response_body(&mut stream, queue, &body_prefix)?;
    Ok(())
}

fn stream_response_body(destination: &mut impl Write, queue: &Path, prefix: &str) -> Result<()> {
    let mut last_progress = Instant::now();
    let done_path = queue.join(format!("{prefix}.done"));
    let mut index = 0usize;
    let mut copied = 0usize;
    loop {
        let body_path = queue.join(format!("{prefix}.body-{index:08}"));
        if body_path.exists() {
            let mut body = fs::File::open(&body_path)?;
            let length = body.metadata()?.len();
            write!(destination, "{length:x}\r\n")?;
            let chunk_length = copy_body(&mut body, destination)?;
            destination.write_all(b"\r\n")?;
            fs::remove_file(body_path)?;
            copied = copied
                .checked_add(usize::try_from(chunk_length)?)
                .context("response size overflow")?;
            index += 1;
            last_progress = Instant::now();
            continue;
        }
        if done_path.exists() {
            let done: BridgeDone = serde_json::from_slice(&fs::read(&done_path)?)?;
            fs::remove_file(done_path)?;
            if let Some(error) = done.error {
                bail!("origin response stream failed: {error}")
            }
            if done.chunks != index || done.body_length != copied {
                bail!(
                    "response stream mismatch: expected {} chunks/{} bytes, got {index}/{copied}",
                    done.chunks,
                    done.body_length
                )
            }
            destination.write_all(b"0\r\n\r\n")?;
            return Ok(());
        }
        if last_progress.elapsed() > Duration::from_secs(60) {
            bail!("HTTP response body timed out")
        }
        thread::sleep(Duration::from_millis(2));
    }
}

fn copy_body(source: &mut impl Read, destination: &mut impl Write) -> Result<u64> {
    let mut buffer = vec![0_u8; 256 * 1024];
    let mut copied = 0_u64;
    loop {
        let read = source.read(&mut buffer)?;
        if read == 0 {
            return Ok(copied);
        }
        destination.write_all(&buffer[..read])?;
        copied += read as u64;
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|part| part == needle)
}

fn is_hop_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "proxy-connection"
            | "keep-alive"
            | "transfer-encoding"
            | "te"
            | "trailer"
            | "upgrade"
    )
}
