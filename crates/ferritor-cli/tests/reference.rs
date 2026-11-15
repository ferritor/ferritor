//! The CLI's reference page (`docs/.../reference/cli.md`) names every
//! command and subcommand, as `ferritor <command> …` in its tables, and
//! every long option of each (the global ones too): a command or an option
//! added later can't go undocumented. Walks the CLI's own definition
//! (clap), so it needs no server.

use clap::CommandFactory as _;
use ferritor_cli::cli::Cli;

const PAGE: &str = include_str!("../../../docs/src/content/docs/reference/cli.md");

/// A command's path (`["namespace", "create"]`), its long options, and
/// whether it's a group (`namespace`, `policy`: it has subcommands).
type Found = (Vec<String>, Vec<String>, bool);

/// clap's own `--help` and `--version`, which no page lists; never an
/// option of ours that happens to share a name (`get --version`).
fn builtin(arg: &clap::Arg) -> bool {
    use clap::ArgAction;
    matches!(
        arg.get_action(),
        ArgAction::Help | ArgAction::HelpShort | ArgAction::HelpLong | ArgAction::Version
    )
}

/// Every command path below `command`, leaves and groups alike.
fn commands(command: &clap::Command, path: &[String], out: &mut Vec<Found>) {
    for sub in command.get_subcommands() {
        if sub.get_name() == "help" {
            continue;
        }
        let mut here = path.to_vec();
        here.push(sub.get_name().to_owned());
        let longs = sub
            .get_arguments()
            .filter(|arg| !arg.is_global_set() && !builtin(arg))
            .filter_map(|arg| arg.get_long().map(str::to_owned))
            .collect();
        out.push((here.clone(), longs, sub.has_subcommands()));
        commands(sub, &here, out);
    }
}

#[test]
fn every_command_and_option_is_on_the_reference_page() {
    let cli = Cli::command();
    let mut found = Vec::new();
    commands(&cli, &[], &mut found);
    assert!(found.len() > 40, "only {} commands found", found.len());
    let mut missing = Vec::new();
    for (path, longs, group) in &found {
        let name = format!("`ferritor {}", path.join(" "));
        let row = PAGE
            .lines()
            .find(|line| line.starts_with(&format!("| {name}`")));
        let row = match row {
            Some(row) => row,
            // A group (`namespace`, `policy`) has no row of its own: its
            // subcommands do. A leaf command always has one.
            None if *group => continue,
            None => {
                missing.push(format!("{name}`"));
                continue;
            }
        };
        for long in longs {
            // `--version`, or with its value: `--label KEY=VALUE`.
            if !row.contains(&format!("`--{long}`")) && !row.contains(&format!("`--{long} ")) {
                missing.push(format!("{name}`: --{long}"));
            }
        }
    }
    for global in cli
        .get_arguments()
        .filter(|arg| !builtin(arg))
        .filter_map(|arg| arg.get_long())
    {
        if !PAGE.contains(&format!("`--{global}`")) {
            missing.push(format!("global --{global}"));
        }
    }
    assert!(
        missing.is_empty(),
        "not on the reference page: {missing:#?}"
    );
}
