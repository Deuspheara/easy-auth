//! Research-only composition of the candidate's existing signing and verification APIs.
mod assertion_cases;
mod cases;
mod engine;
mod fixture;

fn main() {
    if cases::run().is_err() {
        eprintln!("owned_signature_fixture_unavailable");
        std::process::exit(2);
    }
}
