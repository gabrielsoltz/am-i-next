# am-i-next

**What If I'm Next?** is a [TruffleHog](https://github.com/trufflesecurity/trufflehog)
wrapper that scans the locations recent supply-chain attacks have been harvesting
from infected machines, so you can see what an attacker would walk away with if
one of those packages landed on your system.

## Why

A wave of supply-chain attacks (Shai-Hulud, nx "s1ngularity", and many
copycats) shipped credential harvesters inside popular npm/PyPI packages. Once a
malicious `postinstall` hook ran on your machine, it scanned the home
directory for credentials and sent them to attackers.

The harvesters are public; their target lists are documented in the writeups
linked below. `am-i-next` runs TruffleHog over those same locations on **your own
machine** so you can find and rotate exposed secrets *before* an attacker does.

> **For personal/defensive use on machines you own.** This tool only reads and
> reports; it never exfiltrates anything.

## Usage

Requires `trufflehog` and `jq` (used to read the path manifest):

```sh
brew install trufflehog jq        # macOS; see trufflehog docs for other OSes
```

```sh
./am-i-next.sh                       # scan using paths.json + config.conf
./am-i-next.sh --config my.conf      # use a custom config (runtime knobs)
./am-i-next.sh --manifest paths.json # use a custom/fetched path manifest
./am-i-next.sh --no-verify           # skip secrets verification this time.
./am-i-next.sh --scan-env            # also scan the current shell's env vars
./am-i-next.sh --full-home           # scan all of $HOME in one pass (slower)
./am-i-next.sh --report my-scan.log  # override the report path
./am-i-next.sh --json-output out.json # also save the raw trufflehog JSON stream
./am-i-next.sh --verbose             # show each trufflehog invocation
```

Every run writes a human-readable report to `scan-<timestamp>.log` (location set
by `REPORT_DIR` in `config.conf`, or `--report <file>`). It records what was
scanned, any findings, and a summary. **These reports can contain real secret
material**.

### Secrets Verification

TruffleHog can "verify" whether a secret is valid by calling the issuer's API — e.g. hitting AWS STS to check whether an AWS key is actually live. This eliminates false positives, but can introduce false negatives. Each secret ends up in one of three classifications: `verified`, `unverified`, or `unknown`.

`am-i-next` ships with verification **on** by default (`VERIFY=true` in `config.conf`), and only shows you results that are verified. The aim is to eliminate false positives from your results.

If you want to see all the results, add `--results=verified,unverified,unknown` to `TRUFFLEHOG_EXTRA_ARGS` in `config.conf`:
```sh
TRUFFLEHOG_EXTRA_ARGS=(
    "--json"
    "--results=verified,unverified,unknown"   # your value wins; derivation is skipped
)
```

If you don't want your secrets to be verified, you can disable that behavior:

```sh
./am-i-next.sh --no-verify    # skip verification this time
```

### Environment variables

There's no single file containing your environment variables — they live in
each process's memory. The persistent places they get *defined* (shell init
files, launchd plists, systemd unit files) are already in `paths.json` under
the `shell-init` and `system` categories.

For the **current shell's** live environment (whatever is exported right now,
including secrets set in this session that never landed in a file), pass
`--scan-env`:

```sh
./am-i-next.sh --scan-env
```

This dumps `env` to a `chmod 600` temp file under `/tmp`, scans it, and removes
it on exit. It only sees what's exported in the shell you ran the command from
— it won't reach other shells, other users, or other processes' environments.

### Scheduled scans

The interactive `./am-i-next.sh` is the primary way to run a scan, but for an
always-on backstop you can install a per-user scheduled scan via
[`install-schedule.sh`](install-schedule.sh):

```sh
./install-schedule.sh install                                # daily at 03:17 local
./install-schedule.sh install --frequency weekly --time 04:30
./install-schedule.sh status                                  # see next run + last reports
./install-schedule.sh uninstall                               # remove the schedule
```

What it does:

- Writes a per-user **launchd plist** on macOS (`~/Library/LaunchAgents/com.gabrielsoltz.am-i-next.plist`)
  or a per-user **systemd timer + service** on Linux (`~/.config/systemd/user/am-i-next.{timer,service}`).
- Both handle sleep/wake — a missed daily run fires on next wake (launchd) /
  next boot (`Persistent=true` on systemd).
- Reports land in an OS-native, non-synced directory (`chmod 700`):
  - macOS: `~/Library/Application Support/am-i-next/`
  - Linux: `~/.local/state/am-i-next/`
- After each run, `latest.log` symlinks to the newest report and reports older
  than `--retain N` (default 30) are pruned.
- A **desktop notification** fires after every run (findings or clean) with a
  **count-only payload** — no detector names, no values, no leakage via
  Notification Center / lock-screen previews. If the scheduled run itself fails
  (missing dependency, manifest error, etc.), a separate **"Scheduled scan
  failed"** notification fires with the exit code and a pointer to the stderr
  log (`launchd.stderr.log` on macOS, `journalctl --user -u am-i-next.service`
  on Linux).

The scheduled invocation passes `--no-banner --notify --report-dir ... --retain ...`.
Verification stays on, `--scan-env` is intentionally refused in headless
contexts (the scheduled environment isn't your interactive shell's).

The installer refuses to run as root, refuses to overwrite an existing unit
without `--force`, and warns if your chosen report directory lives inside
iCloud / Dropbox / OneDrive / Google Drive. It also refuses to install if
`trufflehog` or `jq` aren't reachable from your interactive shell — and bakes
the directories holding them into the unit's `PATH`, so the scheduled run
can find Homebrew binaries (which aren't on launchd/systemd's default `PATH`).

## Use the path list without this tool

The locations this tool scans are defined in [`paths.json`](paths.json). You can use that information to scan your device with any other secret-scanning tool.

```sh
# Grab the raw manifest
curl -sSL https://raw.githubusercontent.com/gabrielsoltz/am-i-next/main/paths.json -o paths.json

# Example: expand the common paths and scan each with your own trufflehog
jq -r '.scanLocations.common[].path' paths.json \
  | sed "s|^~|$HOME|" \
  | while read -r p; do [ -e "$p" ] && trufflehog filesystem "$p"; done

# Example: just the macOS browser-profile paths
jq -r '.scanLocations.macos[] | select(.category=="browser") | .path' paths.json
```

The manifest also carries `excludePatterns` — locations and file extensions that generally don't pose a risk.

## What we scan, and why

The scan locations in [`paths.json`](paths.json) are derived directly from the
target lists published in analyses of real attacks. 

If instead you want to scan your full home directory, you can use `--full-home` (or `FULL_HOME_SCAN=true` in the config). In that mode, paths under `$HOME` are skipped as redundant while non-home paths
(`/tmp`, `/etc/*`) are still scanned.

Categories:

| Category | Examples |
|----------|----------|
| Cloud credentials (`cloud`) | `~/.aws`, `~/.azure`, `~/.config/gcloud`, `~/.oci` |
| Container / orchestration (`container`) | `~/.kube`, `~/.docker`, `~/.minikube` |
| SSH keys (`ssh`) | `~/.ssh` |
| Git credentials (`git`) | `~/.gitconfig`, `~/.git-credentials`, `~/.config/gh` |
| Registry / package tokens (`registry`) | `~/.npmrc`, `~/.pypirc`, `~/.gem`, `~/.cargo`, `~/.gradle`, `~/.m2`, `~/.nuget` |
| Infrastructure-as-code (`iac`) | `~/.terraformrc`, `~/.terraform.d` |
| Secrets managers (`secrets-manager`) | `~/.config/op` (1Password CLI), `~/.vault-token` (HashiCorp Vault) |
| VPN / network (`vpn-network`) | `~/.netrc`, `~/.config/wireguard` |
| AI tools — auth + chat history (`ai`) | `~/.claude` (Claude Code creds + chat logs), `~/.codex`, `~/.gemini`, `~/.codeium`, `~/.cursor`, `~/.continue`, Cursor/Windsurf `state.vscdb`, ChatGPT Desktop |
| Crypto wallets (`crypto-wallet`) | `~/.ethereum`, `~/.electrum`, `~/.bitcoin`, Exodus/Electrum/Ledger Live/Phantom app data |
| Browser profiles (`browser`) | Chrome / Brave / Edge / Firefox / Arc `Local Storage` + `IndexedDB` |
| GPG / signing (`gpg`) | `~/.gnupg` |
| Shell history (`shell-history`) | `~/.bash_history`, `~/.zsh_history`, `~/.fish/fish_history` |
| Shell init / env exports (`shell-init`) | `~/.profile`, `~/.bashrc`, `~/.bash_profile`, `~/.zshrc`, `~/.zprofile`, `~/.zshenv`, `~/.config/fish/config.fish`, `~/.direnvrc` |
| Project roots (`project`) | `~/code`, `~/projects`, `~/dev`, `~/workspace`, `~/src` (catches `.env` files, git history) |
| Temporary files (`temp`) | `/tmp` |
| Broad config / data (`config-broad`, `data-broad`) | `~/.config`, `~/.local/share` |
| IDE settings (`ide`) | VS Code, Cursor, Windsurf, JetBrains, GitHub Desktop |
| App data / preferences (`app`, `app-prefs`, `cache`) | Slack, Homebrew cache, macOS `Library/Preferences`, snap, flatpak |
| macOS Keychain (`keychain`) | `~/Library/Keychains` (export artifacts, not the encrypted DB itself) |
| System files (`system`) | `/etc/environment`, `/etc/profile.d` (Linux); `~/Library/LaunchAgents` (macOS, launchd plists often carry `EnvironmentVariables`) |

## Sources

**Shai-Hulud Attacks**
- [Datadog Security Labs — Shai-Hulud 2.0 npm worm analysis](https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/)
- [Microsoft Security Blog — Shai-Hulud 2.0 guidance](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/)
- [StepSecurity — Shai-Hulud: 500+ npm packages compromised](https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised)
- [Checkmarx — Inside Shai-Hulud's Maw](https://checkmarx.com/zero-post/inside-shai-huluds-maw-how-the-npm-worm-exploits-and-propagates/)

**nx "s1ngularity" Attacks**
- [GitGuardian — The Nx s1ngularity Attack: Inside the Credential Leak](https://blog.gitguardian.com/the-nx-s1ngularity-attack-inside-the-credential-leak/)
- [StepSecurity — s1ngularity: Nx build system compromised](https://www.stepsecurity.io/blog/supply-chain-security-alert-popular-nx-build-system-package-compromised-with-data-stealing-malware)
- [Semgrep — NX compromised to steal wallets and credentials](https://semgrep.dev/blog/2025/security-alert-nx-compromised-to-steal-wallets-and-credentials/)
- [GitGuardian s1ngularity-scanner (open-source IOC tool)](https://github.com/GitGuardian/s1ngularity-scanner)

## License

See [LICENSE](LICENSE).
