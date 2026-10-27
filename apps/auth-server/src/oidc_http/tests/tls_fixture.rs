use auth_core::MAX_OIDC_DOCUMENT_BYTES;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use std::{
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};
use tokio_rustls::TlsAcceptor;
use url::Url;

#[derive(Default)]
pub(super) struct Facts {
    pub failed_tls: AtomicUsize,
    pub requests: Mutex<Vec<(String, String)>>,
    pub bodies: Mutex<Vec<Vec<u8>>>,
}

pub(super) struct Fixture {
    pub address: SocketAddr,
    pub certificate: CertificateDer<'static>,
    pub facts: Arc<Facts>,
    task: JoinHandle<()>,
}
impl Fixture {
    pub async fn new() -> Self {
        let certified = rcgen::generate_simple_self_signed(vec!["fixture.invalid".into()]).unwrap();
        let certificate = certified.cert.der().clone();
        let key = PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![certificate.clone()], key.into())
        .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let facts = Arc::new(Facts::default());
        let captured = facts.clone();
        let task = tokio::spawn(async move {
            loop {
                let (stream, _) = listener
                    .accept()
                    .await
                    .expect("test infrastructure: owned listener");
                let mut stream = match acceptor.accept(stream).await {
                    Ok(stream) => stream,
                    Err(_) => {
                        captured.failed_tls.fetch_add(1, Ordering::SeqCst);
                        continue;
                    }
                };
                let sni = stream.get_ref().1.server_name().unwrap_or("").to_owned();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") && request.len() < 16384 {
                    let mut byte = [0];
                    if stream.read_exact(&mut byte).await.is_err() {
                        break;
                    }
                    request.push(byte[0]);
                }
                let request = String::from_utf8(request).unwrap();
                let length = request
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                assert!(length <= 16384, "test infrastructure: bounded request body");
                let mut body = vec![0; length];
                stream
                    .read_exact(&mut body)
                    .await
                    .expect("test infrastructure: complete request body");
                captured.bodies.lock().unwrap().push(body);
                captured
                    .requests
                    .lock()
                    .unwrap()
                    .push((sni, request.clone()));
                let path = request.split_whitespace().nth(1).unwrap_or("");
                let (head, body) = reply(path);
                if stream.write_all(head.as_bytes()).await.is_ok() {
                    if path == "/age" {
                        tokio::time::sleep(Duration::from_millis(1100)).await;
                    }
                    if path == "/stall" || path == "/revoke/stall" {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                    // Rejections deliberately close early; BrokenPipe here is an
                    // expected fixture consequence, never a security assertion.
                    let _ = stream.write_all(&body).await;
                    let _ = stream.shutdown().await;
                }
            }
        });
        Self {
            address,
            certificate,
            facts,
            task,
        }
    }
    pub fn url(&self, path: &str) -> Url {
        Url::parse(&format!(
            "https://fixture.invalid:{}{path}",
            self.address.port()
        ))
        .unwrap()
    }
    pub fn roots(&self) -> rustls::RootCertStore {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.certificate.clone()).unwrap();
        roots
    }
    pub async fn close(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}

fn reply(path: &str) -> (String, Vec<u8>) {
    #[cfg(feature = "apple-grants")]
    if path.starts_with("/revoke/") {
        return super::revocation_reply::reply(path);
    }
    let (status,extra,body)=match path {
        "/invalid-grant"=>("400 Bad Request",String::new(),br#"{"error":"invalid_grant"}"#.to_vec()),
        "/invalid-client"=>("401 Unauthorized",String::new(),br#"{"error":"invalid_client"}"#.to_vec()),
        "/html"=>return ("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 2\r\nConnection: close\r\n\r\n".into(),b"{}".to_vec()),
        "/duplicate-type"=>("200 OK","Content-Type: application/json\r\n".into(),b"{}".to_vec()),
        "/age"=>return ("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: max-age=1\r\nContent-Length: 2\r\nConnection: close\r\n\r\n".into(),b"{}".to_vec()),
        "/redirect"=>("302 Found","Location: https://attacker.invalid/forbidden\r\n".into(),Vec::new()),
        "/declared"=>return (format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",MAX_OIDC_DOCUMENT_BYTES+1),Vec::new()),
        "/chunked"=>{
            let data=vec![b' ';MAX_OIDC_DOCUMENT_BYTES+1];
            let mut body=format!("{:x}\r\n",data.len()).into_bytes();body.extend(data);body.extend(b"\r\n0\r\n\r\n");
            return ("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".into(),body);
        }
        "/encoding"=>("200 OK","Content-Encoding: gzip\r\n".into(),b"{}".to_vec()),
        "/headers"=>("200 OK",format!("X-Large: {}\r\n","x".repeat(17000)),b"{}".to_vec()),
        "/stall"=>return ("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".into(),b"0\r\n\r\n".to_vec()),
        _=>("200 OK",String::new(),b"{}".to_vec()),
    };
    (
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nCache-Control: public, max-age=120\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n",
            body.len()
        ),
        body,
    )
}
