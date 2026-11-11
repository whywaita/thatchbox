# thatchbox

A network device configuration backup collector, in the same family as RANCID and Oxidized. thatchbox logs in to each device over SSH (or telnet for old devices), collects its configuration, removes volatile lines, masks secrets, validates that the output is complete, and pushes the result to a git remote. It has no web UI and no database: history, diffs, search and notifications belong to the git hosting service.

Personal addresses, hostnames, IDs and tokens are configuration and are never part of the code or tests.

## Install

- Binaries for Linux and macOS (amd64, arm64) are attached to each [release](https://github.com/whywaita/thatchbox/releases), with `checksums.txt`.
- Container image: `ghcr.io/whywaita/thatchbox:<version>` (for example `0.1.0`; also `<major>.<minor>` and `latest`). `main` and `sha-<commit>` track the main branch. Images are built for linux/amd64 and linux/arm64.
- From source: `go install github.com/whywaita/thatchbox/cmd/thatchbox@latest`

Design decisions, scope and deferred work are in [docs/design.md](docs/design.md).

## How a run works

```text
shallow clone ──> collect every enabled device in parallel ──> validate ──> write configs/<device>/
                                                                               │
                         exit code (non-zero if any device failed) <── push <── commit (only if something changed)
```

Each run is stateless. One run collects every device, commits once, pushes, and exits. A failed device does not stop the others: successful devices are pushed, the failed device keeps its previous files, and the exit code is non-zero so a scheduler or Alertmanager can notice.

## Usage

```sh
thatchbox run \
  --inventory inventory.yaml \
  --repo git@github.com:example/network-configs.git \
  --git-ssh-key /var/run/secrets/thatchbox/deploy-key \
  --git-known-hosts /etc/thatchbox/git_known_hosts

thatchbox validate --inventory inventory.yaml   # check inventory and drivers only
thatchbox drivers                                # list drivers
```

| Flag | Meaning |
|---|---|
| `--inventory` | Inventory YAML (required). See [examples/inventory.yaml](examples/inventory.yaml). |
| `--repo` | Any git remote URL or local path (required). Network remotes are cloned with depth 1; local paths are served in process (no git binary) and cloned in full. |
| `--branch` | Branch to update (default `main`). An empty remote or a missing branch starts a new history. |
| `--git-ssh-key`, `--git-known-hosts` | SSH key for the push (for example a deploy key with write access to that repository only) and the remote's known_hosts. The host key is always verified. |
| `--drivers` | Directory of extra driver YAML files. A file with a built-in name overrides it. |
| `--workdir` | Clone directory. By default a temporary directory that is removed afterwards. |
| `--author-name`, `--author-email` | Commit author. |
| `--log-level` | `debug`, `info`, `warn`, `error`. Logs are JSON on stderr. |

Exit codes: `0` all devices succeeded, `1` some devices failed (the rest were pushed), `2` configuration, clone, commit or push error.

## Inventory

```yaml
defaults:
  concurrency: 8          # parallel devices
  timeout: 2m             # per device, including login
  known_hosts: /etc/thatchbox/known_hosts
  min_size_ratio: 0.5     # reject output smaller than half of the stored version
credentials:
  netadmin:
    username: backup                                   # literal allowed for usernames only
    password: {file: /var/run/secrets/thatchbox/pw}    # or {env: NAME}
    private_key: {file: /var/run/secrets/thatchbox/key}
    private_key_passphrase: {file: /var/run/secrets/thatchbox/key-pass}  # only for an encrypted key
    enable_password: {env: THATCHBOX_ENABLE}
jump_hosts:
  bastion: {address: bastion.example.net, credential: netadmin}
devices:
  - name: core-sw1        # becomes configs/core-sw1/ ; [A-Za-z0-9._-]
    address: 192.0.2.10
    driver: cisco_ios
    credential: netadmin
    transport: ssh        # optional: ssh (default) or telnet
    jump: bastion         # optional, SSH only
    enabled: true         # optional, default true
    ssh:                  # optional; "+name" appends to the defaults, plain names replace them
      kex: ["+diffie-hellman-group1-sha1"]
      ciphers: ["+aes128-cbc"]
      host_key_algorithms: ["+ssh-rsa"]
```

A credential needs a password, a private key, or both. SSH devices and jump hosts also need a username. The key is offered first, then the password (also used for keyboard-interactive prompts), so the same credential works for devices that accept either one and for servers that require the key and then the password. Encrypted keys need `private_key_passphrase`. The same applies to jump hosts.

Passwords, keys, passphrases and enable passwords cannot be written literally; they are read from a file or an environment variable at run time, so the inventory itself can live in a ConfigMap or a public place. Every device needs `known_hosts`; there is no option to skip host key verification. Legacy SSH algorithms are never offered unless enabled for that device.

### Telnet

For devices whose SSH cannot be used, set `transport: telnet`. Telnet is cleartext and has no host key, so use it only on a trusted management network.

```yaml
credentials:
  vty:                     # no username: a vty line password
    password: {file: /var/run/secrets/thatchbox/vty}
    enable_password: {file: /var/run/secrets/thatchbox/enable}
devices:
  - {name: old-sw, address: 192.0.2.30, driver: cisco_ios, credential: vty, transport: telnet}
```

The port defaults to 23 (`defaults.port` applies to SSH only), and `known_hosts` and `ssh` are ignored. thatchbox answers `Username:` / `login:` with the username and `Password:` with the password; a credential without a username works for line passwords. If the device asks again after the password, the device fails with reason `auth`. Telnet devices cannot use jump hosts.

## Output repository

```text
status.json                     # per device: driver, state, reason, last_success, last_failure
configs/<device>/<path>         # one or more files per device, as defined by its driver
```

A device's directory is replaced as a whole on success, so a device can produce a tree of files. `status.json` is rewritten only when a configuration or a device's state or reason changes, so repeated identical runs make no commits; its timestamps are as of the last commit. `reason` is a short category (`connect`, `host-key`, `auth`, `timeout`, `closed`, `enable`, `incomplete`, `device-error`, `empty`, `shrunk`, `credential`, ...) and never contains device output.

Removing a device from the inventory does not delete its files; delete them in the output repository if needed.

## Drivers

Built-in: `cisco_ios` (IOS / IOS-XE), `junos`, `nec_ix` (UNIVERGE IX). `cisco_ios` and `nec_ix` have been checked against real devices (Catalyst 3560-CG, IX2215); `junos` is tested against simulated sessions only. `nec_ix` enters configuration mode with `enable-config` before `show running-config`, using `enable_password` if the device asks for one. A driver is YAML, so a new model needs no code:

```yaml
name: example_os
prompt: '^[\w.\-]+[>#]\s*$'          # the login prompt; the exact prompt is learned after login
enable:                              # optional
  when: '>\s*$'                      # prompt that needs enable
  command: enable
  password_prompt: '(?i)^password:\s*$'
setup: [terminal length 0]           # optional; errors are ignored
pager: {pattern: '--More--\s*$', send: ' '}   # optional fallback when setup cannot disable paging
error: '^% '                         # optional; a matching line fails the collection
drop: ['^! Last change: ']           # volatile lines removed before committing
replace: [{pattern: '...', with: '...'}]
mask: ['^\s*password (?P<secret>\S+)']        # the "secret" group becomes <masked>
mask_blocks: [{begin: '...', end: '...'}]     # lines between are replaced by <masked>
outputs:
  - path: running-config             # file under configs/<device>/
    command: show running-config
    end: '^end$'                     # optional; must match the last non-empty line
    drop: []                         # optional per-output additions (also replace, mask)
```

PEM private key blocks are masked for every driver. Unknown keys and mask patterns without a `secret` group are rejected when loading.

## Validation

A collection is committed only when all of these hold; otherwise the previous files stay and the device is marked failed:

- the device prompt came back after every command (no timeout, no closed connection),
- no line matches the driver's `error` pattern,
- the last non-empty line matches the output's `end` pattern, when defined,
- the output is not empty,
- the total size is at least `min_size_ratio` of the stored version (per device override available).

## Container

`Dockerfile` builds a static binary on `distroless/static:nonroot`, cross-compiling for the target platform. It runs without root and without capabilities (reachability is the TCP connection itself; no ICMP). It needs a writable temporary directory for the clone.

## Tests

All tests live in `tests/` and need no network or external services: SSH devices and jump hosts are simulated by an in-process SSH server, telnet devices by an in-process telnet server, and the git remote is a local bare repository.

```sh
make check     # gofmt, go vet, go test -race ./...
make cover     # coverage of every package into coverage.out
```

Go 1.26 or newer is required.

## Releases

Pushing a tag `vX.Y.Z` runs `.github/workflows/release.yaml`: the tests, a GitHub release with the archives from `make dist`, and the multi-platform image on ghcr.io. A tag with a suffix (`v1.0.0-rc.1`) makes a prerelease. CI (`.github/workflows/ci.yaml`) builds the image on pull requests and publishes `main` and `sha-<commit>` from the main branch.

## License

MIT. See [LICENSE](LICENSE).
