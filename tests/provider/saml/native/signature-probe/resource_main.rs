//! Isolated resource observation composition; no production authentication authority.
mod assertion_cases;
mod cases;
mod engine;
mod fixture;
mod resource_cases;

fn main() {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    let result = if arguments.is_empty() {
        cases::run()
    } else {
        resource_cases::run(&arguments)
    };
    if result.is_err() {
        eprintln!("owned_signature_resource_fixture_unavailable");
        std::process::exit(2);
    }
}
