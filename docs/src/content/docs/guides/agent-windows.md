---
title: 'Agent on Windows Server'
description: 'ferritor-agent on Windows Server: the configuration, what differs from Linux (access lists, links, the process lock), and running it as a service.'
seo:
  title: 'ferritor-agent on Windows Server'
---

The agent runs on **Windows Server** too (tested on
Windows Server 2025, and in CI on its runner): the same agent, the same
configuration and the same directory, with Windows' own mechanisms in
place of the Unix ones. Desktop Windows isn't a target: Windows 11's Smart
App Control, where it's on, refuses to run a binary no publisher signed,
and the agent isn't signed by one.

> [!NOTE]
> This page is what differs on Windows Server. Everything else,
> the settings, the directory and how to read it, the failures and the
> backoff, the metrics, is in [Agent on Linux](/guides/agent), which
> holds what both platforms share.

## Configuration

The settings are [the agent's](/guides/agent#configuration), with Windows
paths:

```toml
server = "https://ferritor.internal:7070"
ca = 'C:\ProgramData\ferritor\ca.pem'
cert = 'C:\ProgramData\ferritor\agent.crt'
key = 'C:\ProgramData\ferritor\agent.key'

[[output]]
dir = 'C:\ProgramData\ferritor\secrets\app'
allow_disk = true                      # required: Windows has no tmpfs
group = 'NT SERVICE\app'              # who reads the files: an account or group
on_change = { command = ["powershell", "-NoProfile", "-Command", "Restart-Service app"] }

[[output.secret]]
path = "billing/app/db-password"
```

Single-quoted TOML strings keep the backslashes as they are.

`app` here is the application's own Windows service. A Windows service has
no reload, so the example restarts it, which interrupts it: if the
application re-reads the files itself (watching `..data`, or reading them
on each use), leave `on_change` unset.

## What differs

| | Linux | Windows |
|---|---|---|
| Who may read a file | its mode and group | an access list the agent sets on each file and directory, nothing inherited: the agent's account, SYSTEM and Administrators everything; `group` (an account or group name, `DOMAIN\name`, `NT SERVICE\app`, `BUILTIN\Users`) reads a file whose mode gives the group read, and lists the directories |
| The directory | must be in memory, unless `allow_disk` | always on a disk: `allow_disk = true` is required. Encrypt the disk (BitLocker) |
| `..data` and the names | symbolic links | Windows' symbolic links, the same layout and the same one-rename swap. Making them takes the **Create symbolic links** privilege: LocalSystem (a service's default account) and elevated administrators have it; for another account grant it (`secpol.msc`, Local Policies, User Rights Assignment), or turn on Developer Mode. Without it the agent refuses to start, saying so |
| A file held open | the old generation is removed at the next write | most Windows programs open files so they can't be deleted: a generation one of its files is open in stays until it's closed, and is removed at the first write after (logged meanwhile, never a failed write) |
| Its memory | undumpable (`PR_SET_DUMPABLE`) | its process's access list, and each of its threads', lets its own account only wait for it, end it and query it, never read its memory, take over a thread or change a list; SYSTEM and administrators with `SeDebugPrivilege` still can. The token's default access list says the same, so a thread started later gets it. An `on_change` command starts with the default list the token had before, like any other process of the account |
| Telling the application | a signal or a command | a command, an `.exe` found as the path given, else in the system directory, the Windows directory or `PATH` (never the current directory). Not a batch file (refused: run it through `"cmd.exe", "/c"`). Its output goes to the agent's console if it has one, nowhere as a service |
| Stopping | SIGTERM, SIGINT | Ctrl+C, Ctrl+Break, the console closing, a shutdown; as a service, the service control manager's stop |

Reading a consistent set works as on Linux: resolve `..data` once, then
read the files under it.

## Getting it

Each release has `ferritor-agent-<version>-x86_64-pc-windows-gnu.zip`
(the agent alone, x86_64), verified like the CLI's archives
([production](/getting-started/production#1-the-binaries)). It isn't signed by a
publisher, so SmartScreen asks first for a browser's download; on Windows
Server there's nothing else in the way.

## Running it

By hand, from a console: `ferritor-agent.exe run --config C:\ProgramData\ferritor\app.toml`
(or `once`), as on Linux; Ctrl+C stops it.

As a service, the same `run` command line, registered with
`New-Service` or `sc.exe` (not PowerShell's `sc` alias). Started by the
service control manager, `run` reports to it and stops at its stop;
started any other way it's a console program. From an elevated
PowerShell:

```powershell
New-Item -ItemType Directory C:\ProgramData\ferritor -Force
# Only SYSTEM and Administrators: the agent's key and config are in here.
icacls C:\ProgramData\ferritor /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F"
Copy-Item ferritor-agent.exe C:\ProgramData\ferritor\

New-Service -Name ferritor-agent-app -StartupType Automatic `
  -BinaryPathName '"C:\ProgramData\ferritor\ferritor-agent.exe" run --config C:\ProgramData\ferritor\app.toml --log-file C:\ProgramData\ferritor\app.log'
sc.exe failure ferritor-agent-app reset= 86400 actions= restart/5000
Start-Service ferritor-agent-app
```

or with `sc.exe create ferritor-agent-app start= auto binPath= "…"`, the
same command line. Any service name works. `--log-file` is where the logs
go, appended, instead of stderr: a service has no console, so without it
nothing is logged. It runs as LocalSystem unless given an account
(`-Credential`, `obj=`): an account of its own needs the link privilege
granted, read access to the config, the key and the CA, and write access
to the output directory's parent. To render once before the application
starts, run `ferritor-agent.exe once --config …` first, as `ExecStartPre`
does under systemd. `Stop-Service ferritor-agent-app` stops it: the files
stay as they are.

## The agent's own key file

The agent's own key file isn't the agent's to protect: whatever
created it decides who can read it, and a folder under `C:\ProgramData`
inherits a list that lets every user read. Lock the folder down as above
before putting the key in it.
