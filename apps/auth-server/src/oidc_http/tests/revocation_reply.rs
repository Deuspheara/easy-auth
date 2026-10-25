// Responses from an owned TLS listener only; never sent to a real provider.
pub(super) fn reply(path: &str) -> (String, Vec<u8>) {
    let (status, headers, body) = match path {
        "/revoke/empty" => ("200 OK", "", Vec::new()),
        "/revoke/nonempty" => (
            "200 OK",
            "Content-Type: application/json\r\n",
            b"{}".to_vec(),
        ),
        "/revoke/missing-type" => ("200 OK", "", b"{}".to_vec()),
        "/revoke/error" => (
            "400 Bad Request",
            "Content-Type: application/json\r\n",
            br#"{"error":"invalid_grant"}"#.to_vec(),
        ),
        "/revoke/config" => (
            "401 Unauthorized",
            "Content-Type: application/json\r\n",
            br#"{"error":"invalid_client"}"#.to_vec(),
        ),
        "/revoke/encoding" => ("200 OK", "Content-Encoding: gzip\r\n", Vec::new()),
        "/revoke/duplicate-encoding" => (
            "200 OK",
            "Content-Encoding: identity\r\nContent-Encoding: identity\r\n",
            Vec::new(),
        ),
        "/revoke/duplicate-type" => (
            "200 OK",
            "Content-Type: application/json\r\nContent-Type: application/json\r\n",
            Vec::new(),
        ),
        "/revoke/html" => ("200 OK", "Content-Type: text/html\r\n", Vec::new()),
        "/revoke/redirect" => (
            "302 Found",
            "Location: https://attacker.invalid/forbidden\r\n",
            Vec::new(),
        ),
        "/revoke/large" => (
            "200 OK",
            "Content-Type: application/json\r\n",
            vec![b' '; 16 * 1024 + 1],
        ),
        "/revoke/chunked" => {
            let data = vec![b' '; 16 * 1024 + 1];
            let mut body = format!("{:x}\r\n", data.len()).into_bytes();
            body.extend(data);
            body.extend(b"\r\n0\r\n\r\n");
            return ("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".into(), body);
        }
        "/revoke/stall" => {
            return (
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".into(),
                b"0\r\n\r\n".to_vec(),
            );
        }
        _ => panic!("test infrastructure: unknown revocation fixture path"),
    };
    (
        format!(
            "HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        ),
        body,
    )
}
