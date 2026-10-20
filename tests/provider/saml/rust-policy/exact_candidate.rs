//! Research-only composition of the patched upstream profile and existing driver.
#[path = "../comparison/rust_candidate.rs"]
mod comparison;

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--strict") {
        comparison::main();
    } else if comparison::run_with_options(
        |options| {
            options.xml_signature_profile = Some(saml_rs::XmlSignatureProfile::StrictRsaSha256);
        },
        "exact-flow",
        false,
    )
    .is_err()
    {
        eprintln!("exact_policy_comparison_failed");
        std::process::exit(2);
    }
}
