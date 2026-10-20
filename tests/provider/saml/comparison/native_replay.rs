//! Replay private synthetic corpus bytes through the existing native probe engine.
mod assertion_cases;
mod cases;
mod engine;
mod fixture;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use samael::crypto::{CertificateDer, ReduceMode};
use std::io::{self, BufRead, Read};

fn main() {
    let result = if std::env::args().nth(1).as_deref() == Some("--replay") {
        replay()
    } else {
        cases::run()
    };
    if result.is_err() {
        eprintln!("native_comparison_transport_failed");
        std::process::exit(2);
    }
}

fn replay() -> fixture::Result<()> {
    for line in io::stdin().lock().take(2 * 1024 * 1024).lines() {
        let line = line?;
        let fields: Vec<_> = line.split('\t').collect();
        if fields.len() != 4 {
            return Err("invalid_transport_row".into());
        }
        let mode = match fields[1] {
            "rooted" => ReduceMode::ValidateAndMarkNoAncestors,
            "predigest" => ReduceMode::PreDigest,
            _ => return Err("invalid_mode".into()),
        };
        let xml = String::from_utf8(STANDARD.decode(fields[2])?)?;
        let certs = fields[3]
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|cert| STANDARD.decode(cert).map(CertificateDer::from))
            .collect::<Result<Vec<_>, _>>()?;
        engine::emit(fields[0], mode, &xml, &certs);
    }
    Ok(())
}
