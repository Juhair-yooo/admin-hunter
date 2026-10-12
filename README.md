# AdminHunter v1.0.0

Admin portal discovery & admin-user exposure assessment tool for authorized
security testing. Built for Kali Linux; runs anywhere with Python 3.8+.

AdminHunter helps a tester answer two questions about a target they are
authorized to assess:

1. **Where is the admin panel?** (subdomains, common paths, control-panel
   ports, CMS-specific paths, robots.txt hints)
2. **Is the server leaking who uses it?** (public `mod_status`/`stub_status`
   pages, world-readable access logs, exposed `.env`/`.git`, WordPress user
   enumeration)

---

## ⚠️ Legal & Ethical Use — Read First

This tool performs active reconnaissance and enumeration against a live
target: DNS lookups, port connections, and HTTP requests to many paths in
a short time window. That is unauthorized access / computer misuse in most
jurisdictions unless you have permission.

**Only run this against:**
- Infrastructure you personally own
- A target covered by a signed penetration-testing engagement or scope
  document, with written authorization from the owner
- An in-scope target under a bug bounty program's published rules
- A lab/CTF environment built for practice (HackTheBox, TryHackMe,
  Metasploitable, DVWA, etc.)

**Do not** run it against production systems, third-party companies, or
anything you don't have explicit written authorization to test — including
"just checking" out of curiosity. Unauthorized use may violate laws such as
the Computer Fraud and Abuse Act (US), the Computer Misuse Act (UK),
Malaysia's Computer Crimes Act 1997, and equivalent legislation elsewhere.

The author and this README accept no responsibility for misuse. The
"authorized-security-testing" string in the tool's User-Agent is a
courtesy disclosure to the target, not a legal shield — it does not make
unauthorized use legal.

---

## Requirements

- Python 3.8 or later
- `requests` library
- Network access to the target (and, for port scanning, outbound TCP to
  the ports being probed)

## Installation

```bash
# 1. Place adminhunter.py in a working directory
mkdir -p ~/tools/adminhunter
cd ~/tools/adminhunter
# (copy adminhunter.py into this folder)

# 2. Install the one dependency
pip install requests

# 3. (optional) make it executable
chmod +x adminhunter.py
```

No other setup is required — the script is a single file. Python's
standard library covers everything else (threading, sockets, regex, etc.).

## Optional: custom wordlist

By default AdminHunter uses a built-in list of ~70 common admin paths. For
deeper coverage, point it at a larger wordlist with `-w`, e.g. one from
SecLists (commonly pre-installed on Kali at
`/usr/share/seclists/Discovery/Web-Content/`):

```bash
-w /usr/share/seclists/Discovery/Web-Content/admin-panels.txt
```

Alternatively, drop a file at `wordlists/admin_paths.txt` next to the
script (one path per line, `#` for comments) and it will be picked up
automatically when `-w` is not given.

---

## Basic Usage

```bash
python3 adminhunter.py http://TARGET
```

Example against an authorized lab target:

```bash
python3 adminhunter.py http://10.0.0.5
```

This runs, in order:
1. Target recon (DNS, CDN/WAF detection)
2. CMS/framework fingerprinting
3. robots.txt hint parsing
4. Admin subdomain enumeration
5. Control-panel port probing
6. Admin portal path discovery (wordlist scan with soft-404 filtering)
7. Admin-user exposure checks (mod_status, logs, `.env`, `.git`, WP users)
8. Summary of findings by severity

## Step-by-Step Walkthrough

1. **Confirm authorization.** Have your scope document, bug bounty rules,
   or ownership confirmed before running anything below.
2. **Run a baseline scan** with defaults to get a quick picture:
   ```bash
   python3 adminhunter.py http://TARGET
   ```
3. **Review the summary** at the end of the output — it lists findings by
   severity (critical/high/medium/low/info) and any discovered login pages.
4. **Re-run with a bigger wordlist** if nothing turned up:
   ```bash
   python3 adminhunter.py http://TARGET -w /path/to/wordlist.txt
   ```
5. **Save a report** for your engagement notes:
   ```bash
   python3 adminhunter.py http://TARGET -o report.md --json report.json
   ```
6. **Tune for the environment** as needed — see the options table below
   (e.g. `--skip-ports` on a target where port scanning is explicitly
   out of scope, or `--delay` to go slower on a rate-limited target).
7. **Write up findings** using the generated Markdown/JSON report, mapping
   each item back to the relevant control (e.g. "public mod_status" →
   "server misconfiguration exposing client IPs").

## Command-Line Options

| Flag | Description |
|---|---|
| `target` | Target URL, e.g. `http://10.0.0.5` (required, positional) |
| `-w`, `--wordlist` | Path to a custom admin-path wordlist |
| `-t`, `--threads` | Number of concurrent threads for path scanning (default: 20) |
| `--timeout` | Per-request timeout in seconds (default: 8.0) |
| `--delay` | Delay in seconds between requests, per thread (default: 0, useful for rate-limited targets) |
| `--exts` | Comma-separated extensions to fuzz onto paths, e.g. `php,html` |
| `--proxy` | Route traffic through a proxy, e.g. `http://127.0.0.1:8080` (Burp/ZAP) |
| `--user-agent` | Override the default User-Agent string |
| `--verify-tls` | Verify TLS certificates (off by default for lab/self-signed targets) |
| `--full-ports` | Also probe a secondary list of database/misc service ports |
| `--skip-subs` | Skip admin subdomain enumeration |
| `--skip-ports` | Skip control-panel port probing |
| `--skip-exposure` | Skip the admin-user exposure module (mod_status/logs/.env/.git/WP users) |
| `-o`, `--output` | Write a Markdown report to this file |
| `--json` | Write a JSON report to this file |

## Example Commands

```bash
# Quick recon only, skip the noisier modules
python3 adminhunter.py http://TARGET --skip-subs --skip-ports

# Through Burp Suite for manual follow-up
python3 adminhunter.py http://TARGET --proxy http://127.0.0.1:8080

# Slow, polite scan against a rate-limited target
python3 adminhunter.py http://TARGET -t 5 --delay 0.5

# Full report generation for a client deliverable
python3 adminhunter.py https://TARGET -o findings.md --json findings.json
```

## Understanding the Output

Findings are grouped by severity:

- **Critical/High** — direct data exposure (public access logs, `.env`,
  `.git`, `mod_status` leaking client IPs)
- **Medium** — partial exposure (e.g. `.env` found but no obviously
  sensitive keys)
- **Low** — weak points worth hardening (open control-panel ports,
  enumerable WordPress usernames, exposed Nginx status page)
- **Info** — contextual findings (admin login page located, admin-ish
  subdomain resolves, robots.txt discloses a path)

The final summary states plainly whether admin-user IP data was obtainable
from the target at all — this is the core question the "admin-user
exposure" module answers.

## Interpreting "No findings"

A clean run (no high/critical findings, no exposed logs or status pages)
is a *good* result for the target — it means the common leak channels this
tool checks are closed. It does not mean the target has no vulnerabilities;
AdminHunter only covers the specific exposure classes listed above, not a
full penetration test.

---

## Project Structure

```
adminhunter/
├── adminhunter.py          # main script (not included in this file set)
├── README.md                # this file
├── LICENSE                  # MIT license
└── wordlists/
    └── admin_paths.txt      # optional custom wordlist (not bundled)
```

## Disclaimer

This tool is provided for educational purposes and authorized security
testing only. The author is not responsible for any misuse or damage
caused by this tool. Always obtain proper authorization before testing
any systems you do not own.
