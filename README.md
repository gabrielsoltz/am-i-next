# am-i-next

**What If I'm Next?** a [TruffleHog](https://github.com/trufflesecurity/trufflehog)
wrapper that scans the locations recent supply-chain attacks have been harvesting
from developer machines, so you can see what an attacker would walk away with if
one of those packages landed on your system.

## Why

A wave of supply-chain attacks (Shai-Hulud, nx "s1ngularity", and many
copycats) shipped credential harvesters inside popular npm/PyPI packages. Once a
malicious `postinstall` hook ran on a developer's machine, it scanned the home
directory for cloud keys, SSH keys, registry tokens, and crypto wallets, then
exfiltrated them to attacker-controlled GitHub repos.

The harvesters are public, their target lists are documented in the writeups
linked below. `am-i-next` runs TruffleHog over those same locations on **your own
machine** so you can find and rotate exposed secrets *before* an attacker does.

> **For personal/defensive use on machines you own.** This tool only reads and
> reports; it never exfiltrates anything.

## Usage

```sh
# Install trufflehog first (brew install trufflehog, or the official installer)
./am-i-next.sh                       # scan using config.conf
./am-i-next.sh --verbose             # show each trufflehog invocation
./am-i-next.sh --config my.conf      # use a custom config
./am-i-next.sh --full-home           # scan all of $HOME in one pass (slower)
./am-i-next.sh --report my-scan.log  # override the report path
./am-i-next.sh --json-output out.json # also save the raw trufflehog JSON stream
```

Every run writes a human-readable report to `scan-<timestamp>.log` (location set
by `REPORT_DIR` in `config.conf`, or `--report <file>`). It records what was
scanned, any findings, and a summary. **These reports can contain real secret
material**.

By default the curated path list in `config.conf` is scanned. `--full-home`
(or `FULL_HOME_SCAN=true` in the config) instead scans your entire home
directory the way real harvesters do, more thorough but slower. In that mode,
paths under `$HOME` are skipped as redundant while non-home paths
(`/tmp`, `/etc/*`) are still scanned.

By default only **verified** secrets are reported (`--results=verified` in
`config.conf`). Loosen that flag to surface unverified candidates too.

## What we scan, and why

The scan locations in [`config.conf`](config.conf) are derived directly from the
target lists published in analyses of real attacks. Categories:

| Category | Examples | Seen in |
|----------|----------|---------|
| Cloud credentials | `~/.aws`, `~/.azure`, `~/.config/gcloud`, AWS IMDS metadata | Shai-Hulud, s1ngularity |
| Container / orchestration | `~/.kube`, `~/.docker`, Vault token | Shai-Hulud |
| SSH keys | `~/.ssh`, `id_rsa` | both |
| Registry / package tokens | `~/.npmrc`, `~/.pypirc`, `~/.gem`, `~/.cargo` | both |
| AI CLI tool auth | `~/.claude`, `~/.gemini`, Amazon Q config | s1ngularity (weaponized Claude/Gemini/Q CLIs) |
| AI conversation history | `~/.claude/projects/**/*.jsonl`, `~/.codex/*.sqlite`, Cursor/Windsurf `state.vscdb`, ChatGPT Desktop | ghosttype (secrets pasted into AI prompts are stored locally in plaintext) |
| Crypto wallets | `~/.ethereum`, `~/.electrum`, MetaMask/Exodus/Ledger/Phantom data | both |
| Browser profiles | Chrome/Brave/Edge/Firefox `Local Storage` + `IndexedDB` | s1ngularity |
| `.env` / source repos | project roots, git history | both (TruffleHog used by Shai-Hulud) |
| Shell history & startup | `~/.zsh_history`, `~/.bashrc`, `~/.zshrc` | s1ngularity |

## Sources

These writeups document the attacks and the exact files/locations their
harvesters targeted, the basis for `config.conf`:

**Shai-Hulud (self-replicating npm worm; used TruffleHog to harvest secrets)**
- [Datadog Security Labs — Shai-Hulud 2.0 npm worm analysis](https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/)
- [Microsoft Security Blog — Shai-Hulud 2.0 guidance](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/)
- [StepSecurity — Shai-Hulud: 500+ npm packages compromised](https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised)
- [Checkmarx — Inside Shai-Hulud's Maw](https://checkmarx.com/zero-post/inside-shai-huluds-maw-how-the-npm-worm-exploits-and-propagates/)

**nx "s1ngularity" (credential + wallet stealer; first weaponized AI CLI tools)**
- [GitGuardian — The Nx s1ngularity Attack: Inside the Credential Leak](https://blog.gitguardian.com/the-nx-s1ngularity-attack-inside-the-credential-leak/)
- [StepSecurity — s1ngularity: Nx build system compromised](https://www.stepsecurity.io/blog/supply-chain-security-alert-popular-nx-build-system-package-compromised-with-data-stealing-malware)
- [Semgrep — NX compromised to steal wallets and credentials](https://semgrep.dev/blog/2025/security-alert-nx-compromised-to-steal-wallets-and-credentials/)
- [GitGuardian s1ngularity-scanner (open-source IOC tool)](https://github.com/GitGuardian/s1ngularity-scanner)

## License

See [LICENSE](LICENSE).
