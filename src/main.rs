//! Ahab binary entry point.

use anyhow::Result;
use clap::Parser;

use ahab::Cli;

fn main() -> Result<()> {
    let cli = Cli::parse();
    cli.run()
}
