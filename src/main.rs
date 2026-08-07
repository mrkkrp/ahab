//! Ahab binary entry point.

use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;

use ahab::cli::Cli;

fn main() -> Result<ExitCode> {
    let cli = Cli::parse();
    cli.run()
}
