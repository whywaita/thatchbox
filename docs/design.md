# thatchbox design

This document records the decisions behind thatchbox, the scope of the first version, and what was deliberately postponed. Keep it current: it describes the present design, not a history.

## Motivation

Network configuration is needed most when the network is broken. A backup that lives on a server inside the same network, or behind the same uplink, is unreachable exactly then. thatchbox therefore pushes to a git remote that is usually hosted elsewhere (for example a private GitHub repository), so the configurations stay readable from outside while the local network is down.

The second goal is that a backup is trustworthy. An output cut off in the middle (a dropped session, a pager that was not answered, a command error) must never replace a good stored version, and secrets must never reach the remote, because removing them from git history afterwards is impractical.

## How it differs from RANCID and Oxidized

- A single static Go binary with no runtime, no database and no web UI.
- Drivers are declarative YAML: prompt, enable, pager, commands, volatile lines, masks and end markers. Adding a model needs no code.
- Every collection is validated (prompt returned, no device error, end marker, non-empty, no sudden shrink against the stored version) before it is committed.

## Architecture

thatchbox is a collector only. Input is an inventory YAML; output is a push to a git remote. History, diff, search and notification are the git host's job.

One run: shallow clone (depth 1) → collect every enabled device in parallel → validate → write `configs/<device>/` → write `status.json` if needed → one commit → push → exit. Nothing is kept between runs; the previous version used for the shrink check is the cloned one.

- **Files, not a file**: a device produces a set of files under its own directory, because some platforms (load balancers, for example) are naturally a tree.
- **One repository for all devices**: per-device repositories are not supported.
- **Partial failure**: one failing device does not fail the run. Successful devices are pushed, the failed device keeps its previous files and gets `state: failed` with a short `reason`, and the process exits `1`. Exit `2` is for configuration, clone, commit or push failures.
- **No empty commits**: volatile lines are removed by the driver, unchanged files are not rewritten, and `status.json` changes only when a configuration, a state, a reason or the device set changes. Its timestamps are as of that commit; the run log and exit code are the per-run truth.
- **Git remote**: any URL go-git can push to. SSH push uses a key given by flag (intended: a deploy key with write access to the backup repository only) and a known_hosts file.

## Security rules

These are requirements, not preferences:

- Host keys are always verified against known_hosts. There is no switch to disable it.
- Legacy SSH algorithms (`ssh-rsa`, `diffie-hellman-group1-sha1`, CBC ciphers, ...) are opt-in per device or jump host.
- Passwords, keys and enable passwords are references (`{env: NAME}` or `{file: PATH}`), never literals in the inventory.
- No user input or device name ever reaches a shell. Git is driven by go-git; nothing is executed through `sh -c`.
- Errors, logs and `status.json` never include terminal output, which may contain secrets. Errors are categories with addresses and file paths only.
- Masking runs before anything is written. Each driver masks password hashes, SNMP communities, pre-shared keys and similar; PEM private key blocks are masked for every driver.
- Device names and output paths are validated so nothing is written outside `configs/<device>/`.
- Telnet is cleartext and is used only for devices that set `transport: telnet`. Such devices have no host key to verify, so keep them on a trusted management network.
- The container runs as non-root with no capabilities. Reachability is the TCP connection itself; ICMP is not used.

## Transports and sessions

The SSH layer is `golang.org/x/crypto/ssh` used directly, not scrapligo: the declarative driver already owns prompts, enable and paging, and using the library directly keeps algorithm selection, known_hosts handling and jump hosts in one small package that can be tested against an in-process server.

- Authentication: public key (optionally encrypted, with a passphrase reference), password, and keyboard-interactive answered with the password. A credential may hold both a key and a password; the key is offered first, so servers requiring both (partial success) work as well as servers accepting either.
- Jump hosts are named in the inventory and referenced by devices; any device can use any jump host.
- The session requests a PTY, waits for the prompt regex, then learns the literal prompt and matches only that for the rest of the session. Enable re-learns the prompt.
- Each device has a timeout covering connect, login and all commands; the number of parallel devices is limited.
- Telnet (`transport: telnet`, port 23 by default) exists for old devices whose SSH cannot be used, such as switches that accept only a vty line password. The client refuses every option except server echo and suppress-go-ahead. Login happens in the stream: a username prompt (`Username:` / `login:`) gets the credential's username, a password prompt gets its password, and a login prompt asked again after the password means rejection (`auth`). A credential without a username is a line password. Telnet devices cannot use jump hosts yet.

## Scope of the first version

Done:

1. Inventory with credentials by group, jump hosts, per-device transport (SSH or telnet), timeout, port, known_hosts, SSH algorithms, shrink ratio and enable flag.
2. Declarative drivers with built-in `cisco_ios`, `junos` and `nec_ix`, overridable from a directory.
3. Normalization of prompts, echoes, pager remnants and volatile lines.
4. Masking.
5. Validation before commit.
6. Device output as a set of files.
7. `status.json` and exit codes.
8. One repository for all devices.

Verified on real devices: `cisco_ios` on a Catalyst 3560-CG over telnet with a line password and enable, and `nec_ix` on an IX2215 over SSH (show running-config needs `enable-config`; the pager cannot be disabled and is answered; there is no end marker). `junos` has been developed against simulated sessions only.

## Deployment

A Kubernetes CronJob with `concurrencyPolicy: Forbid`, the inventory and known_hosts files as a ConfigMap, secrets mounted as files, a read-only root filesystem with an `emptyDir` for the clone, and an egress policy that allows only the devices, DNS and the git host. Devices' management ACLs must allow the address the cluster's egress traffic is translated to. Manifests for a particular cluster are kept with that cluster's configuration, not in this repository.

## Deferred

- **Change notifications**: not in thatchbox. A workflow in the backup repository, triggered by push, can post the changed devices and a link to the diff to a chat service. thatchbox stays free of dependencies outside the network it collects from and the git remote.
- **Metrics endpoint**: not useful for a short-lived job; the exit code and logs are enough for alerting now.
- **Web UI**: not planned.
- **More drivers**: candidates include Cisco ASA / NX-OS / Catalyst 1300, Arista EOS, Huawei, H3C, Dell OS9 / OS10, Cumulus Linux, F5 BIG-IP / F5OS, A10 ACOS, Citrix ADC, Fortinet, Palo Alto, Nokia SR OS, VyOS, YAMAHA RTX and switches, and console servers. Platforms whose configuration is a file tree (for example F5) may need a driver feature for collecting several files from one command or from a file transfer.
- **Telnet through a jump host**: possible with an SSH direct-tcpip channel, not needed yet.
- **Pruning removed devices** from the output repository, and accepting an intentional large shrink without editing `min_size_ratio`.

## Clean-room rule

thatchbox is written from scratch. Do not copy code, templates, parsing definitions, names or logos from other tools whose licenses do not allow it, including internal tools that inspired the feature set. Write driver patterns from device documentation and real output.
