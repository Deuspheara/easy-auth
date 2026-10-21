mod cli;
mod runtime;

use std::process::ExitCode;

fn main() -> Result<ExitCode, Box<dyn std::error::Error>> {
    match cli::parse(std::env::args_os().skip(1)) {
        Ok(cli::Command::Serve) => runtime::serve()?,
        Ok(cli::Command::Help) => print!("{}", cli::HELP),
        Ok(cli::Command::Version) => println!("easy-auth {}", env!("CARGO_PKG_VERSION")),
        Err(()) => {
            // Arguments may contain credentials; never echo unrecognized input.
            eprintln!("invalid command line; run easy-auth --help");
            return Ok(ExitCode::from(2));
        }
    }
    Ok(ExitCode::SUCCESS)
}
