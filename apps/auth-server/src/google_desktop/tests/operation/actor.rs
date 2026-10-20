use super::super::GoogleDesktopSignIn;
use auth_core::Secret;
use std::{process::Command, time::Duration};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
};

// Python is the documented CI/development runtime. All inputs are separate argv
// data, never shell interpolation. This actor never contacts an external endpoint.
const SCRIPT: &str = r#"
import os,sys,socket,stat,time,urllib.parse
for descriptor in (0,1,2):
 info=os.fstat(descriptor); null=os.stat(os.devnull)
 if not stat.S_ISCHR(info.st_mode) or info.st_rdev != null.st_rdev:sys.exit(29)
mode,url,code,observer=sys.argv[1:]
print('owned-private-output-must-be-suppressed')
print('owned-private-error-must-be-suppressed',file=sys.stderr)
if observer:
 host,port=observer.rsplit(':',1)
 signal=socket.create_connection((host,int(port)),timeout=2)
 signal.sendall(b'owned-started')
if mode=='wait':time.sleep(60)
elif mode=='exit':sys.exit(0)
elif mode=='fail':sys.exit(17)
else:
 fields=urllib.parse.parse_qs(urllib.parse.urlsplit(url).query,strict_parsing=True)
 redirect=urllib.parse.urlsplit(fields['redirect_uri'][0])
 if redirect.hostname not in ('127.0.0.1','::1'):sys.exit(28)
 result={'state':fields['state'][0],'iss':'https://accounts.google.com'}
 if mode in ('access_denied','server_error'):
  result.update(error=mode,error_description='owned-private-provider-detail')
 else:result['code']=code
 query=urllib.parse.urlencode(result)
 connection=socket.create_connection((redirect.hostname,redirect.port),timeout=3)
 connection.sendall(('GET '+redirect.path+'?'+query+' HTTP/1.1\r\nHost: '+redirect.netloc+'\r\n\r\n').encode('ascii'))
 response=b''
 while True:
  chunk=connection.recv(4096)
  if not chunk:break
  response+=chunk
  if len(response)>16384:sys.exit(26)
 if not response.startswith(b'HTTP/1.1 200'):sys.exit(25)
 if mode=='callback_then_fail':sys.exit(17)
"#;

pub(super) fn command(
    attempt: &GoogleDesktopSignIn,
    code: Option<&Secret>,
    mode: &str,
    observer: Option<&Observer>,
) -> Command {
    let mut command = Command::new("python3");
    command
        .arg("-c")
        .arg(SCRIPT)
        .arg(mode)
        .arg(attempt.start.authorization_url.expose())
        .arg(code.map_or("", Secret::expose))
        .arg(observer.map_or(String::new(), |value| {
            value.listener.local_addr().unwrap().to_string()
        }));
    command
}
pub(super) struct Observer {
    listener: TcpListener,
}
impl Observer {
    pub async fn new() -> Self {
        Self {
            listener: TcpListener::bind("127.0.0.1:0").await.unwrap(),
        }
    }
    pub async fn started(&self) -> TcpStream {
        let (mut stream, _) = tokio::time::timeout(Duration::from_secs(2), self.listener.accept())
            .await
            .expect("test infrastructure: owned opener started")
            .unwrap();
        let mut marker = [0; 13];
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut marker))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&marker, b"owned-started");
        stream
    }
    pub async fn closed(mut stream: TcpStream) {
        let mut bytes = Vec::new();
        let result = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut bytes))
            .await
            .expect(
                "test infrastructure: owned opener connection must close within observation cap",
            );
        if let Err(error) = result {
            assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
        }
        assert!(bytes.is_empty(), "only the owned start marker is sent");
    }
}
