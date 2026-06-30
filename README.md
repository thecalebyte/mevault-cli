# MeVault CLI

A local-first secret manager for developers that keeps credentials away from AI coding agents, using Windows named pipes and kernel-level process identity rather than environment variables or bearer tokens.

```powershell
mevault init
mevault add DATABASE_URL
mevault unlock
mevault run uvicorn app.main:app --reload
```

Your server reads secrets directly from a named pipe. Claude, Copilot, Cursor: none of them can reach those values, even if they try to spawn your server themselves.

---

> **What's in this repository**
>
> This repo hosts release artifacts for two separate products:
>
> | Download | What it is | Source |
> |---|---|---|
> | `mevault-windows-x64.exe` | **CLI** — the open-source command-line tool | ✅ This repo (`cli-v*` releases) |
> | `MeVault_*_x64-setup.exe` / `.msi` | **Desktop app** — GUI + system tray | Closed source (`app-v*` releases) |
>
> The CLI (`mevault-cli`), core library (`mevault-core`), and Rust SDK (`mevault-sdk`) are open source under Apache 2.0. The desktop app source is not publicly available.

---

## The problem

AI coding agents run in your terminal. They can read environment variables, `.env` files, shell history, and any file in your project. When you give an agent access to fix a bug, it potentially has access to every credential loaded in your session.

Most "secret management" solutions put secrets into environment variables, which agents can read just as easily as your own code can.

MeVault is different: **secrets are never placed into environment variables**. Processes that need a secret call a named pipe (`\\.\pipe\mevault-runtime`). The pipe server identifies the caller using the Windows kernel (not based on anything the caller claims) and only returns the secret if the process passes all identity checks.

## How it works

```
┌──────────────────────────────────────────────────────────────┐
│ Your machine                                                 │
│                                                              │
│  mevault unlock              mevault run node server.js      │
│       │                              │                       │
│       ▼                              ▼                       │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              MeVault Pipe Server                    │    │
│  │                                                     │    │
│  │  \\.\pipe\mevault-runtime   (secret requests)       │    │
│  │  \\.\pipe\mevault-control   (management commands)   │    │
│  │                                                     │    │
│  │  For every request:                                 │    │
│  │  1. GetNamedPipeClientProcessId  (kernel PID)       │    │
│  │  2. PID + creation-time grant match                 │    │
│  │  3. Resolve full exe path                           │    │
│  │  4. Walk parent process chain (up to 5 levels)      │    │
│  │  5. Verify Authenticode signature (WinVerifyTrust)  │    │
│  │  6. Check hardcoded always-deny list                │    │
│  │  7. Match allow-list rules in mevault.toml          │    │
│  │  8. Check working directory matches project root    │    │
│  │  9. Decrypt only the requested secret               │    │
│  │  10. Return value, write audit log                  │    │
│  └─────────────────────────────────────────────────────┘    │
│                    │                                         │
│  node ✓   uvicorn ✓   claude.exe ✗   cursor.exe ✗          │
└──────────────────────────────────────────────────────────────┘
```

### What makes this different from environment variables

| Approach | Agent can read it? |
|---|---|
| `.env` file | Yes, it's just a file |
| Environment variables | Yes, agents inherit your shell env |
| Bearer token in env | Yes, any env var is readable |
| MeVault named pipe | No, the kernel decides who gets through |

### Why named pipes instead of HTTP

The previous version used an HTTP proxy at `127.0.0.1:52731`. Named pipes are strictly stronger:

- The kernel provides the caller PID directly via `GetNamedPipeClientProcessId`, with no TCP port mapping heuristic
- No localhost port that other processes can discover and connect to
- No bearer token that can be stolen from the environment or `session.json`
- PID recycling attacks are blocked by binding a creation-timestamp grant at connection time

### Trust model

1. **Vault**: per-project envelope-encrypted file (v2 format). Argon2id derives a Key-Encryption Key (KEK) from your password; the KEK unwraps a random 256-bit Data-Encryption Key (DEK); the DEK encrypts the secrets payload with AES-256-GCM. Each vault has a stable `vault_id` baked into the authenticated data (AAD), preventing ciphertext from one vault being transplanted into another.
2. **Session DEK**: the DEK is cached in memory (`Zeroizing<[u8;32]>`) for the session lifetime. Argon2id runs **once** at unlock — not on every secret access. The KEK is zeroized immediately after unwrapping the DEK. When the session is locked or a time-based expiry fires, the DEK is zeroized automatically via RAII drop.
3. **Pipe server**: the only runtime path to a secret value; bound to named pipes, not the network
4. **Kernel PID**: `GetNamedPipeClientProcessId` provides the real caller PID; the caller cannot forge this
5. **Creation-time grant**: each connection records `(PID, creation_timestamp)`; re-verified on every request to detect PID recycling
6. **Allow-list**: `mevault.toml` declares which executables, from which parents, in which directory, may access which secrets
7. **Always-deny list**: AI agent executables are hardcoded as denied and cannot be overridden
8. **System policy**: `%ProgramData%\MeVault\policy.toml` is admin-writable only; it overrides project config so agents cannot weaken security by editing `mevault.toml`

### Request flow

Every pipe request goes through all checks in sequence. Any failure means deny and log. No exceptions.

```
1.  GetNamedPipeClientProcessId      : kernel-provided PID, not caller-supplied
2.  Verify PID + creation timestamp  : detects PID recycling attacks
3.  Resolve full exe path            : QueryFullProcessImageNameW
4.  Walk parent process chain        : up to 5 levels
5.  Verify code signature            : WinVerifyTrust (Authenticode)
6.  Always-deny list                 : hardcoded, cannot be configured off
7.  Allow-list rules in mevault.toml : exe path, parent, working dir, secret name
8.  Working directory check          : must match the project root
9.  Decrypt requested secret         : only that one secret, on demand
10. Return value, write audit log entry
```

## Platform support

| Platform | Status |
|---|---|
| Windows 10 / 11 | Available now |
| macOS | Coming soon |
| Linux | Coming soon |

The core named-pipe IPC and identity model is Windows-specific today. macOS and Linux support (via Unix domain sockets and `/proc`-based identity) is on the roadmap.

## Installation

### CLI (`mevault.exe`) — open source

**winget (recommended)**

```powershell
winget install MeVault.MeVaultCLI
```

**Direct download**

Download `mevault-windows-x64.exe` from the [latest `cli-v*` release](https://github.com/thecalebyte/mevault-cli/releases), rename it to `mevault.exe`, and place it somewhere on your `PATH`.

### Desktop app — closed source

Download `MeVault_*_x64-setup.exe` (NSIS installer) or `MeVault_*_x64_en-US.msi` from the [latest `app-v*` release](https://github.com/thecalebyte/mevault-cli/releases). The desktop app includes the CLI and adds a system tray icon, a secrets dashboard, and a policy editor.

### Build from source

```powershell
git clone https://github.com/thecalebyte/mevault-cli.git
cd mevault-cli
cargo build -p mevault-cli --release
# Binary at: target\release\mevault.exe
```

Requires Rust stable. Links against Windows system libraries only, with no other runtime dependencies.

### Windows Smart App Control

Windows 11 Smart App Control (SAC) may block `mevault.exe` if it was downloaded directly from the internet. **The recommended fix is to install via winget**, as winget-distributed binaries are reviewed by Microsoft and are always trusted by SAC.

If you downloaded the binary directly and SAC blocks it, unblock it with:

```powershell
Unblock-File -Path ".\mevault.exe"
```

Or right-click the file, open **Properties**, tick **Unblock**, and click OK.

Binaries built from source locally are never blocked because they carry no Mark of the Web.

## Quick start

```powershell
# 1. One-time setup per project
cd C:\Projects\myapp
mevault init

# 2. Add secrets (prompted with hidden input, never on the command line)
mevault add DATABASE_URL
mevault add OPENAI_API_KEY
mevault add JWT_SECRET

# 3. Option A: persistent session (leave running in a terminal)
mevault unlock
# Vault unlocked.
#   Runtime pipe : \\.\pipe\mevault-runtime
#   Control pipe : \\.\pipe\mevault-control
# Press Ctrl+C or run `mevault lock` to lock the vault.

# 4. Your app reads secrets via the SDK (see below)
node server.js
python app.py

# Or, Option B: ephemeral session (vault locks when your app exits)
mevault run node server.js
mevault run uvicorn app.main:app --reload
mevault run -- cargo run --release
```

## How applications read secrets

Secrets are **never** placed in environment variables. Your application connects to `\\.\pipe\mevault-runtime` and requests one secret at a time. The pipe server verifies the caller's identity before returning anything.

### Rust SDK

Add `mevault-sdk` to your `Cargo.toml`:

```toml
[dependencies]
mevault-sdk = "0.1"
```

```rust
use mevault_sdk::get;
use secrecy::ExposeSecret;

fn main() -> mevault_sdk::Result<()> {
    let db_url = get("DATABASE_URL")?;
    let conn = connect(db_url.expose_secret());
    // db_url is a SecretString, zeroized from memory when it drops
    Ok(())
}
```

`get()` is synchronous. `list()` returns the names your process is permitted to access.

### Node.js

```javascript
const net = require('net');

function getSecret(name) {
  return new Promise((resolve, reject) => {
    const client = net.createConnection('\\\\.\\pipe\\mevault-runtime');
    client.write(JSON.stringify({ op: 'get_secret', name }) + '\n');
    client.once('data', (data) => {
      client.destroy();
      const resp = JSON.parse(data);
      resp.ok ? resolve(resp.value) : reject(new Error(resp.reason));
    });
  });
}

const dbUrl = await getSecret('DATABASE_URL');
```

### Python

```python
import json

def get_secret(name):
    with open(r'\\.\pipe\mevault-runtime', 'rb+', buffering=0) as pipe:
        pipe.write((json.dumps({'op': 'get_secret', 'name': name}) + '\n').encode())
        resp = json.loads(pipe.readline())
    if resp['ok']:
        return resp['value']
    raise RuntimeError(resp.get('reason', 'denied'))

db_url = get_secret('DATABASE_URL')
```

### Wire protocol

The runtime pipe uses newline-delimited JSON (one request per connection). Requests are limited to 4 096 bytes; responses to 1 MB. The server closes connections that exceed these limits or that do not send data within 10 seconds.

```
→  {"op":"get_secret","name":"DATABASE_URL"}\n
←  {"ok":true,"value":"postgres://..."}\n

→  {"op":"list_secrets"}\n
←  {"ok":true,"names":["DATABASE_URL","REDIS_URL","JWT_SECRET"]}\n

←  {"ok":false,"error":"access_denied","reason":"parent process is claude.exe"}\n
```

Optional fields for clients that want correlation:

```json
{"op":"get_secret","name":"DATABASE_URL","protocol_version":1,"request_id":"550e8400-..."}
```

`protocol_version` defaults to `1` if omitted. `request_id` is echoed back in the response when present.

## Commands

### `mevault init`

First-time setup for a project. Creates an encrypted vault file and writes `mevault.toml`.

```powershell
mevault init
mevault init --name "AuthService"
```

### `mevault add`

Add a secret to the vault. Value is always prompted, never passed as a CLI argument.

```powershell
mevault add DATABASE_URL
mevault add JWT_SECRET --generate       # auto-generate a secure random value
mevault add --from-env .env             # import all KEY=VALUE pairs from a .env file
```

### `mevault unlock`

Unlock the vault and start both named pipe servers. Prompts for your vault password.

```powershell
mevault unlock
```

```
Vault unlocked.
  Runtime pipe : \\.\pipe\mevault-runtime
  Control pipe : \\.\pipe\mevault-control
Press Ctrl+C or run `mevault lock` to lock the vault.
```

The session stays open until you lock it. No credentials are written to the environment or disk. Argon2id runs once at unlock and derives a session DEK that is held in memory, zeroized on lock. Each secret request reads the encrypted payload from disk and decrypts it with the cached DEK — no password or KDF work required after the initial unlock. If `expiry_mode` is `time` or `both`, a background task automatically zeroizes the DEK when the timer fires.

### `mevault run <command>`

Unlock inline, run a command, then lock automatically when it exits. The child and all processes it spawns are placed in a Windows Job Object; they are all killed when the command exits, preventing orphaned processes from retaining pipe access.

```powershell
mevault run node server.js
mevault run uvicorn app.main:app --reload
mevault run python manage.py runserver
mevault run -- cargo run --release      # use -- to separate flags
```

If `mevault unlock` is already running, `mevault run` re-uses the existing session instead of unlocking a new one.

### `mevault lock`

Gracefully lock the vault. Sends a shutdown signal over the control pipe; the server drains in-flight requests, zeroizes the session, and exits.

```powershell
mevault lock
```

### `mevault status`

Show the current session state by querying the control pipe.

```powershell
mevault status
```

```
Status: active
  Vault: AuthService
```

### `mevault list`

List secret names. If a session is active, queries the live pipe (no password needed). Falls back to prompting for the vault password if no session is running. Values are never shown.

```powershell
mevault list
mevault list --vault "AuthService"
```

### `mevault verify <name>`

Check that a secret matches an expected value using constant-time comparison. Does not print the stored value. Exit code: `0` = match, `1` = mismatch, `2` = error.

```powershell
mevault verify DATABASE_URL
# Prompts: "Expected value: " (hidden input)
# Outputs: ✓ match  or  ✗ mismatch
```

### `mevault get <name> --reveal`

Print the plaintext value of a secret to stdout. Requires `allow_cli_reveal = true` in `mevault.toml` and must be run in an interactive terminal (not piped). The reveal is written to the audit log.

```powershell
mevault get DATABASE_URL --reveal
```

### `mevault config validate`

Parse and validate `mevault.toml`. Checks rule syntax, wildcard double opt-in, and whether configured executables exist on disk.

```powershell
mevault config validate
```

### `mevault config migrate`

Back up `mevault.toml` and convert old `[[allow_list.rules]]` entries to the current `[[process]]` format.

```powershell
mevault config migrate
```

### `mevault doctor`

Check all system components: CLI version, `mevault.toml`, vault file, active session, pipe health, policy, SDK availability, and auto-updater.

```powershell
mevault doctor

# Show which rule would match a given executable and whether it would be allowed:
mevault doctor --command python.exe
```

### `mevault log`

View the audit log. Every pipe request, whether allowed or denied, is recorded. Secret values are never logged.

```powershell
mevault log
mevault log --tail 20
mevault log --type denied
mevault log --secret DATABASE_URL
mevault log --since 24h
mevault log --export audit.json
```

```
Timestamp             Event     Secret          Process        Reason
2026-01-01 09:00:01   allowed   DATABASE_URL    node.exe
2026-01-01 09:00:04   denied    DATABASE_URL    claude.exe     always_deny
2026-01-01 09:01:12   denied    OPENAI_API_KEY  python.exe     not_in_allowlist
```

### `mevault export`

Export secrets for backup or migration. Only encrypted formats are supported; plaintext export has been intentionally removed.

```powershell
mevault export                          # AES-256-GCM encrypted .env.mvenc (default)
mevault export --format mvx             # encrypted .mvx bundle
mevault export --output backup.mvx
```

### `mevault import`

Import secrets from an encrypted export file.

```powershell
mevault import backup.mvx
mevault import secrets.env.mvenc
```

## Configuration

### `mevault.toml`

Created by `mevault init`. Defines the process rules for your project.

```toml
[project]
name = "AuthService"
vault_name = "AuthService"
created_at = "2026-01-01T00:00:00Z"

[session]
expiry_mode = "both"      # "terminal" | "time" | "both"
expiry_hours = 8

[security]
unknown_process_mode = "deny_and_log"
require_identity_check = true
require_signature_check = true
require_parent_check = true
require_working_dir_check = true
allow_cli_reveal = false   # set true to allow `mevault get <name> --reveal`

[[process]]
name = "node"
executable = "node.exe"
working_dir = "${PROJECT_ROOT}"
secrets = ["DATABASE_URL", "REDIS_URL"]
allow_all_secrets = false

[[process]]
name = "uvicorn"
executable = "uvicorn.exe"
working_dir = "${PROJECT_ROOT}"
secrets = ["DATABASE_URL", "REDIS_URL"]
allow_all_secrets = false

# To allow access to ALL secrets, both fields are required:
[[process]]
name = "my-trusted-app"
executable = "myapp.exe"
working_dir = "${PROJECT_ROOT}"
secrets = ["*"]
allow_all_secrets = true   # explicit double opt-in required
```

Use `mevault config validate` to check your rules, and `mevault config migrate` to convert old `[[allow_list.rules]]` configs to the new `[[process]]` format.

### System policy (`%ProgramData%\MeVault\policy.toml`)

This file is writable only by administrators. It overrides `mevault.toml` security settings, so AI agents cannot weaken your security by editing the project config file.

```toml
require_identity_check = true
require_signature_check = true
```

## Always-deny list

These executables are **hardcoded** as denied. This list cannot be modified or configured off, not by `mevault.toml` and not by system policy.

```
claude.exe          claude-code.exe     copilot.exe
cursor.exe          windsurf.exe        codeium.exe
github-copilot.exe
```

A process is also denied if **any process in its parent chain** appears on this list. Running your server from inside a Claude Code terminal means the server is denied; the agent is in its parent chain.

## Security model

### What MeVault protects against

| Threat | How |
|---|---|
| Agent reads env vars | Secrets are never placed in env vars |
| Agent reads session token | No session token exists; kernel PID is the gate |
| Agent steals `session.json` | File contains only `session_id`, `vault_name`, `pid` — no DEK, no password |
| Agent spawns an approved process | Parent chain check catches the agent |
| Agent edits `mevault.toml` | System policy (`%ProgramData%`) overrides project config |
| Process impersonates approved exe | Authenticode signature check via WinVerifyTrust |
| PID recycling attack | Creation timestamp bound at connection time, re-verified per request |
| Port scanning / localhost probe | Named pipes have no port; not discoverable by network scanning |
| Cross-vault ciphertext transplant | `vault_id` is baked into AES-GCM AAD; decryption fails if moved |
| Vault file corruption mid-write | Atomic rename via UUID temp file; `sync_all` before promotion |
| V1 vault upgrade data loss | Migration requires a verified backup before the new file is promoted |
| Password change exposes old DEK | Password change rewraps the existing DEK; no re-encryption of secrets |

### What MeVault does not protect against

| Threat | Notes |
|---|---|
| Kernel-level rootkits | If the kernel is compromised, nothing helps |
| Administrator-level attackers | Admins can write system policy and access protected storage |
| Physical machine access | Relies on Windows user account security |

### Why there is no bearer token

Earlier versions used `MEVAULT_TOKEN` in the environment and a token in `session.json`. That was removed because:

1. Any process that inherits the environment, including an agent, could steal the token
2. Tokens in `session.json` were readable by any process running as the same user

The current design uses only the kernel-provided process identity. There is nothing in the environment or on disk that an agent can steal to impersonate an approved process.

## Project structure

```
crates/
  mevault-core/       shared library: IPC, identity, grants, config, audit, crypto
    src/
      ipc/            named pipe servers (runtime + control) and protocol
      identity/       Win32 process identity, Authenticode, Job Objects
      grants/         LaunchGrant registry (PID + creation-timestamp key)
      session/        session lifecycle, DEK caching and auto-expiry
      vault/          per-project envelope-encrypted vault store (v2 KEK/DEK format)
      audit/          SQLite audit log
      config/         TOML config parsing (ProcessRule) and system policy
      crypto/         AES-256-GCM + Argon2id for vault and export/import
      export/         export/import module (.env.mvenc / .mvx formats)
    tests/
      grants_security.rs    PID-reuse, wildcard opt-in, zero-timestamp panic

  mevault-cli/        CLI binary: argument parsing, calls mevault-core
    src/
      main.rs
      commands/       one file per subcommand

  mevault-sdk/        Rust SDK for applications that read secrets at runtime
    src/
      lib.rs          get() + list(), sync named-pipe client
```

## Contributing

`mevault-cli`, `mevault-core`, and `mevault-sdk` are open source under the Apache 2.0 licence. The MeVault broker service and desktop UI are separate private products.

Pull requests are welcome for:
- Bug fixes
- New allow-list rule presets for common runtimes
- SDK implementations for other languages (Node, Python, .NET)
- macOS / Linux backend (coming soon, via Unix domain sockets + proc identity)

Please open an issue before starting significant work.

## Licence

Apache 2.0. See [LICENSE](LICENSE).
