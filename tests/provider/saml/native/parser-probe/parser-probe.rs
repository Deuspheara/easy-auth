//! Research overlay only: exercise upstream's exact parser defaults, not SAML verification.
use libxml::parser::Parser;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
use std::time::Duration;

const MARKER: &str = "auth32-owned-marker";
const SENTINEL: &str = "/tmp/auth32-owned-sentinel";

fn main() {
    if run().is_err() {
        eprintln!("owned_parser_probe_unavailable");
        std::process::exit(2);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 2 {
        return Err("explicit_case_and_trap_port_required".into());
    }
    let case = &args[0];
    let port: u16 = args[1].parse()?;
    if port == 0 {
        return Err("trap_port_required".into());
    }
    if case == "file-control" {
        emit(case, None, std::fs::read_to_string(SENTINEL)? == MARKER);
    } else if case == "http-control" {
        emit(case, None, http_control(port)?);
    } else {
        let xml = xml_input(case, port).ok_or("unknown_probe_case")?;
        match Parser::default().parse_string(xml) {
            Ok(document) => {
                let matches = document
                    .get_root_element()
                    .is_some_and(|root| root.get_content() == MARKER);
                emit(case, Some(true), matches);
            }
            Err(_) => emit(case, Some(false), false),
        }
    }
    Ok(())
}

fn xml_input(case: &str, port: u16) -> Option<String> {
    Some(match case {
        "healthy" => format!("<probe>{MARKER}</probe>"),
        "doctype" => format!("<!DOCTYPE probe><probe>{MARKER}</probe>"),
        "internal-entity" => format!(
            "<!DOCTYPE probe [<!ENTITY marker '{MARKER}'>]><probe>&marker;</probe>"
        ),
        "file-entity" => format!(
            "<!DOCTYPE probe [<!ENTITY marker SYSTEM 'file://{SENTINEL}'>]><probe>&marker;</probe>"
        ),
        "http-entity" => format!(
            "<!DOCTYPE probe [<!ENTITY marker SYSTEM 'http://127.0.0.1:{port}/entity'>]><probe>&marker;</probe>"
        ),
        "external-dtd" => format!(
            "<!DOCTYPE probe SYSTEM 'http://127.0.0.1:{port}/dtd'><probe>{MARKER}</probe>"
        ),
        "parameter-entity" => format!(
            "<!DOCTYPE probe [<!ENTITY % remote SYSTEM 'http://127.0.0.1:{port}/dtd'>%remote;]><probe>{MARKER}</probe>"
        ),
        "malformed" => format!("<probe>{MARKER}"),
        "multiple-roots" => format!("<probe>{MARKER}</probe><second/>"),
        _ => return None,
    })
}

fn http_control(port: u16) -> Result<bool, Box<dyn std::error::Error>> {
    let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
    let mut stream = TcpStream::connect_timeout(&address.into(), Duration::from_secs(2))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(b"GET /control HTTP/1.0\r\nHost: localhost\r\n\r\n")?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response.ends_with(MARKER))
}

fn emit(case: &str, parsed: Option<bool>, marker: bool) {
    let parsed = parsed.map_or_else(|| "null".into(), |value| value.to_string());
    println!(r#"{{"case":"{case}","parse_accepted":{parsed},"marker_matches":{marker}}}"#);
}
