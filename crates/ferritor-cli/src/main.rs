use std::process::ExitCode;

use clap::Parser;
use ferritor_cli::cli::Cli;

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match ferritor_cli::run(&cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            if let Some(hint) = ferritor_cli::hint(&cli.command, &error) {
                eprintln!("hint: {hint}");
            }
            // `ferritor audit verify`: unproven isn't broken.
            if error.downcast_ref::<ferritor_cli::Unproven>().is_some() {
                ExitCode::from(2)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}
