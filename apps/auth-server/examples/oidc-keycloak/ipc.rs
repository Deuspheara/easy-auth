use super::FixtureResult;
use std::io::{BufRead, Write};

pub(crate) fn read_command(input: &mut impl BufRead) -> FixtureResult<Option<serde_json::Value>> {
    let mut line = String::new();
    if input.read_line(&mut line)? == 0 {
        return Ok(None);
    }
    if line.len() > 65536 {
        return Err("fixture IPC bound exceeded".into());
    }
    Ok(Some(serde_json::from_str(&line)?))
}
pub(crate) fn send(value: serde_json::Value) -> FixtureResult<()> {
    // stdout is a private pipe owned by the runner, never a user-facing log.
    let mut output = std::io::stdout().lock();
    serde_json::to_writer(&mut output, &value)?;
    writeln!(output)?;
    output.flush()?;
    Ok(())
}
