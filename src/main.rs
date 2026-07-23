//! Ahab binary entry point.

use anyhow::Result;
use clap::Parser;

use ahab::Cli;

fn main() -> Result<()> {
    let cli = Cli::parse();
    let container = cli.run()?;

    // First approximation: just dump the parsed message and exit 0.
    println!("{container:#?}");

    Ok(())
}
