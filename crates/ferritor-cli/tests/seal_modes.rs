//! `rekey start --seal`'s values are the server's seal modes, so a new
//! auto-unseal provider can't be left out of the CLI.

use clap::CommandFactory as _;
use ferritor_cli::cli::Cli;
use ferritor_server::seal::SealMode;

#[test]
fn the_seal_option_offers_every_seal_mode() {
    let command = Cli::command();
    let start = command
        .find_subcommand("rekey")
        .and_then(|rekey| rekey.find_subcommand("start"))
        .unwrap();
    let seal = start
        .get_arguments()
        .find(|arg| arg.get_id() == "seal")
        .unwrap();
    let offered: Vec<String> = seal
        .get_possible_values()
        .iter()
        .map(|value| value.get_name().to_owned())
        .collect();
    let modes: Vec<String> = SealMode::ALL
        .iter()
        .map(|mode| mode.as_str().to_owned())
        .collect();
    assert_eq!(offered, modes);
}
