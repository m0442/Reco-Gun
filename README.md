# RecoGun

![Bash](https://img.shields.io/badge/bash-5.x-4EAA25?logo=gnubash&logoColor=white)
![Platform](https://img.shields.io/badge/platform-Linux-informational)
![Status](https://img.shields.io/badge/status-personal%20project-blue)
![License](https://img.shields.io/badge/license-private-lightgrey)

**Automated recon + crawling methodology for bug bounty and authorized
penetration testing.** Aggregates 20+ passive sources, resolves and probes
what's live, checks for takeovers, crawls for endpoints, and — as an opt-in
step — hunts for the real origin IP behind a WAF/CDN. Every run diffs
against your last one, so re-running against a target tells you what's
*new*, not just what's there.

> **Authorized use only.** This tool is built for bug bounty programs and
> engagements you are explicitly authorized to test. It performs no
> exploitation and sends no attack payloads — but scanning a target without
> permission is on you, not the tool. Respect program scope (`--scope`/`--oos`
> exist for exactly this) and rate limits.

## Table of contents

- [Quick start](#quick-start)
- [Commands](#commands)
- [Targets (auto-detected)](#targets-auto-detected)
- [Options](#options)
- [Methodology](#methodology-what-each-phase-does)
- [Bundled defaults](#bundled-defaults-wordlists--resolvers)
- [Feature guides](#feature-guides)
- [Output layout](#output-layout)
- [Troubleshooting](#troubleshooting)
- [Migrating from v5](#migrating-from-v5)
- [Architecture notes](#architecture-notes)
- [Credential hygiene](#credential-hygiene)

## Quick start

```bash
git clone <this-repo>
cd RecoGun
cp config.env.example config.env   # fill in whichever API keys you have
chmod +x recogun.sh
./recogun.sh check                 # see what tools/keys are available
./recogun.sh scan example.com      # default recon
```

The UI is `recogun <command> <target> [options]`. You pick *what to do* with a
command, point it at a *target* (RecoGun figures out whether it's a domain, a
list of domains, or a list of hosts), and tweak with a few options.

## Commands

| Command | What it runs |
|---|---|
| `scan <target>` | Default recon — enum → probe → takeover |
| `full <target>` | Everything — enum, bruteforce, probe, origin, ports, takeover, crawl |
| `enum <target>` | Only find subdomains |
| `probe <target>` | enum + httpx (which subdomains are live) |
| `crawl <target>` | Only crawl (waymore/waybackurls/gau/katana) |
| `origin <target>` | Only origin-IP-behind-WAF discovery |
| `ports <target>` | enum + probe + passive port discovery (`naabu -passive`) |
| `takeover <target>` | enum + probe + subdomain-takeover checks |
| `run <phases> <target>` | Custom combo, e.g. `run enum,crawl example.com` |
| `check` | Report which tools/API keys are available, then exit |
| `update` | Check for a newer RecoGun version, then exit |

Phase names for `run`: `enum`, `bruteforce`, `probe`, `origin`, `ports`,
`takeover`, `crawl`.

## Targets (auto-detected)

The one target argument is classified automatically:

| You pass | Detected as | Behavior |
|---|---|---|
| `example.com` | a domain | scanned directly |
| a file of bare roots (`example.com`, one per line) | domains file | each enumerated from scratch |
| a file of full hosts (`api.example.com`, …) | hosts file | split by registered root domain; each root's hosts fed straight into the phases (no re-enum) |

So `recogun crawl hosts.txt -o out/` crawls a mixed list of live hosts and
writes one `out/<root>.txt` per domain — no flags to remember for input type.

## Options

| Option | Description |
|---|---|
| `-o <dir>` | Collect each domain's main output as `<dir>/<root>.txt` (one file per root domain) |
| `-j <n>` | Max parallel tool jobs (default 8) |
| `-v` | Verbose — log the actual command run per tool (API keys redacted) |
| `--scope <file>` | Include-only scope (exact subs or `*.domain.tld`, one per line) |
| `--oos <file>` | Out-of-scope list (same format) — dropped from results |
| `--wordlist <file>` | Custom bruteforce wordlist (default: bundled) |
| `--resolvers <file>` | Custom resolvers list (default: bundled) |
| `--perms <file>` | Custom permutation wordlist (default: bundled) |
| `--exclude <t1,t2>` | Skip these tools by name (e.g. `--exclude katana,amass`) |

Every run prints a one-line summary (command, phases, target kind) before it
starts, so you can see exactly what's about to happen.

## Methodology (what each phase does)

1. **enum** — passive subdomain enumeration (parallel, capped by `-j`) across
   20+ sources; merged, deduped, scope-filtered.
2. **origin** — origin-IP-behind-WAF discovery, domain-level, runs once.
   `wafw00f` fingerprints the WAF/CDN; candidate IPs come from VirusTotal
   historical resolutions, AlienVault OTX, URLScan.io, a Shodan
   `ssl.cert.subject.CN` search, `uncover`, and Shodan favicon-hash search.
   Each candidate gets a direct GET (`curl --resolve`, Host header spoofed)
   compared against the normal response's status + `<title>` — a heuristic,
   not proof; matches land in `verified_origin_ips.txt`.
3. **bruteforce** — resolvers validated first (dead ones dropped);
   dnsgen/alterx permutate *from subdomains already found*, resolved via
   shuffledns; puredns bruteforces a wordlist; dnsrecon runs standard
   enumeration. Re-merged, re-filtered. Skipped automatically on wildcard DNS.
4. **probe** — httpx confirms live hosts, diffed against the previous run.
5. **ports** — `naabu -passive`, no direct scanning of the target.
6. **takeover** — subzy against live subdomains.
7. **crawl** — waymore, waybackurls, gau, katana (parallel); merged, diffed,
   deduped with `uro`, split into JS files and API-shaped endpoints. If
   `paramx` is installed, parameterized URLs are tagged by likely vuln class
   for triage — classification only, no payloads sent.

Every run also writes `report.txt` (human) and `report.json` (machine-readable),
and diffs subdomains / active hosts / URLs against the previous run for the
same domain (new-since-last-scan, no flag needed).

## Bundled defaults (wordlists & resolvers)

Three files ship in the repo so `full`/`bruteforce` work straight after
cloning, with no extra downloads:

- `resolvers.txt` — 21 major public resolvers
- `wordlists/subdomains.txt` — SecLists' `subdomains-top1million-5000` (5,000 entries), used by `puredns` for wordlist bruteforce
- `wordlists/permutations.txt` — [six2dez/OneListForAll](https://github.com/six2dez/OneListForAll)'s `permutations_short.txt` (1,069 entries — `dev`, `staging`, `api`, `www1`-`www7`, etc.), used by `dnsgen` and (only with `--perms`) `alterx`

All three resolve relative to the script's own location, not your current
directory, so they work no matter where you run RecoGun from. Pass
`--wordlist`/`--resolvers`/`--perms` to use your own instead.

**Note on `--perms`:** without it, `alterx` runs with `-en` (enrichment —
*adds* words pulled from your already-found subdomains on top of its own
curated list). `alterx`'s built-in word list is purpose-built for its DSL
patterns, so RecoGun doesn't silently swap it out for a generic wordlist —
`--perms` only replaces alterx's `word` payload outright when you pass it.

## Feature guides

### Setting up the `origin` phase

Most origin sources work off `config.env` keys, but three tools read their
**own** config and will fail opaquely (403 / "no keys found") if not set up.
RecoGun warns about each at the start of the `origin` phase; here's the fix
for each:

- **`shodan`** (used by `shodan-cert` + favicon-hash search) — needs its own
  one-time auth even with `SHODAN_API_KEY` in `config.env`:
  ```bash
  shodan init <your-shodan-key>
  shodan info      # should print your plan + query credits, not an error
  ```
  A 403 here also means your Shodan plan may not include `search`.

- **`uncover`** — reads `~/.config/uncover/provider-config.yaml`, not
  `config.env`. Create it with the keys you have (any subset works; blank
  ones are skipped):
  ```yaml
  # ~/.config/uncover/provider-config.yaml
  shodan: [ "YOUR_SHODAN_KEY" ]
  censys: [ "API_ID:API_SECRET" ]
  fofa:   [ "EMAIL:FOFA_KEY" ]
  quake:  [ "QUAKE_KEY" ]
  hunter: [ "HUNTER_KEY" ]
  netlas: [ "NETLAS_KEY" ]
  ```

- **OTX / AlienVault** (`otx-ips` + the `alienvault` enum source) — OTX now
  rate-limits anonymous access. Add a free key to `config.env`:
  ```
  OTX_API_KEY=your_otx_key    # from otx.alienvault.com -> Settings -> API
  ```

VirusTotal sources use the **v3** API (the old v2 `/vtapi/v2` endpoints were
shut down and returned non-JSON, breaking the sources — fixed as of v6.1).

### Crawl a list of hosts you already have

Point `crawl` at a file of live hosts. RecoGun groups them by registered
root domain (public-suffix aware via `tldextract`) and crawls each root
separately. Add `-o <dir>` to get one output file per domain:

```bash
# hosts.txt mixes *.shutterfly.com and *.shutterfly.net hosts
recogun crawl hosts.txt -o out/
# => out/shutterfly.com.txt  and  out/shutterfly.net.txt
```

The same works for `takeover` or `ports` on an existing host list. `-o`
also works on any command — e.g. `recogun enum domains.txt -o subs/` drops
one subdomain file per domain into `subs/`.

### Scope files (`--scope` / `--oos`)

One entry per line, `#` for comments:

```
example.com          # exact match
*.dev.example.com     # wildcard - base domain and any subdomain of it
```

`--scope` (include) is applied first as a whitelist, `--oos` (exclude) after.
Both re-apply following bruteforce, since that phase can generate names
outside your intended scope.

### Incremental scans

If a previous `results/<domain>_*` run exists, RecoGun automatically diffs
against the most recent one and reports `new_subdomains.txt`,
`new_active_subdomains.txt`, and `crawling/new_urls.txt` — the actual new
attack surface since last time, not the full list again. No flag needed;
just re-run the same target periodically, e.g. from cron:

```bash
0 */6 * * * cd /path/to/RecoGun && ./recogun.sh scan target.com >> cron.log 2>&1
```

### Multi-domain progress

When the target is a file (of domains or hosts), each one gets a `[N/Total]`
prefix on its start/summary/done lines, so a long list running unattended
shows exactly where it is, and a final banner reports which domains (if any)
had takeovers or tool errors across the whole run.

### Auto-update check (`update`)

Every run auto-checks for updates (`git fetch`, 10s timeout) before scanning.
In a real terminal, it asks `[y/N]` before pulling; in a non-interactive
session (cron, CI) it never prompts — it just logs that an update exists and
continues with the current version, so automated runs can never hang waiting
on stdin that will never arrive. Run `recogun update` to check on demand.

## Output layout

```
results/<domain>_<timestamp>/
├── sources/                 raw output per passive-enum tool
├── bruteforce/               permutation + wordlist bruteforce raw output (-b)
├── origin_ip/                 candidate + verified origin IPs (-o)
├── crawling/
│   ├── final_crawling_results.txt
│   ├── filtered_urls.txt      (uro-deduped)
│   ├── javascript_files.txt
│   ├── api_endpoints.txt
│   ├── new_urls.txt           (vs. previous run)
│   └── paramx/{xss,sqli,...}.txt
├── final_subdomains.txt
├── active_subdomains.txt
├── new_subdomains.txt / new_active_subdomains.txt   (vs. previous run)
├── takeovers.txt              (only if subzy found something)
├── naabu.txt                  (ports)
├── recogun.log
├── report.txt
└── report.json
```

## Troubleshooting

### Crawling tools erroring out on large targets

If `waybackurls`/`gau-crawl`/`katana` show `[X] Error ... Skipping to the next
tool` right after several minutes, it's almost always a timeout, not a real
tool failure — those three process every active subdomain, and a target with
a few hundred live hosts can take well past the default budget. The crawling
phase already fans work out internally (`gau --threads`, `waybackurls` via
`xargs -P`, `katana -c`, all scaled by `-j`), but if you're scanning a large
target, bump the crawl-specific timeout in `config.env`:

```bash
CRAWL_TIMEOUT_SECONDS=3600   # default is 1800 (30 min)
```

This is separate from `TIMEOUT_SECONDS`, which stays short (default 300s)
for the quick API-based passive-enum sources.

### `bruteforce` takes 24h on one domain, httpx never finishes

This is wildcard DNS, not a performance bug. If `*.domain.tld` resolves to
*something* for any subdomain you query, every single wordlist/permutation
guess "succeeds" as a false positive — the candidate list explodes to the
size of your wordlist, and `httpx` then has to probe all of it one by one.
RecoGun checks for this automatically before running the bruteforce phase:
two random, near-certainly-nonexistent subdomains are resolved, and if both
answer, the phase is skipped for that domain with a loud warning instead of
silently producing garbage. `httpx` also runs with explicit concurrency
(`HTTPX_THREADS`, default 100) and a 5s per-host timeout, and logs a warning
if more than 20,000 subdomains get queued for probing regardless of cause.

## Migrating from v5

v6 replaced the flag soup with subcommands. Old commands no longer work —
here's the translation:

| Old (v5) | New (v6) |
|---|---|
| `-d example.com` | `scan example.com` |
| `-d example.com -b -p -o -C` | `full example.com` |
| `-l domains.txt` | `scan domains.txt` |
| `-d example.com --only enum` | `enum example.com` |
| `--only crawl -f hosts.txt -O out/` | `crawl hosts.txt -o out/` |
| `-d x --only takeover` | `takeover x` |
| `-x oos.txt -i in.txt` | `--oos oos.txt --scope in.txt` |
| `-e katana` | `--exclude katana` |
| `-w / -r / -m <file>` | `--wordlist / --resolvers / --perms <file>` |
| `-c` | `check` |
| `-u` | `update` |
| `-O <dir>` (capital) | `-o <dir>` (there's only one `-o` now, always a folder) |

Note `-o` changed meaning: in v5 lowercase `-o` was origin-IP discovery
(now the `origin` command) and capital `-O` was output. In v6 there's a
single `-o <dir>` = output folder.

## Architecture notes

- All error tracking goes through a per-run file (`.tool_errors`) rather
  than an in-memory array, so it stays correct when tools run in parallel.
- `run_tools_parallel` takes an array of `"name:command"` pairs and a target
  directory, fanning them out with a `PARALLEL_JOBS` concurrency cap
  (default 8, override with `-j` or `PARALLEL_JOBS` in `config.env`).
- The subcommand layer is thin: each command just maps to an explicit phase
  list, and the same `process_domain` engine runs those phases. Adding a
  command is one line in `set_phases_for_command`.

## Credential hygiene

`config.env` holds live API keys — it's gitignored, keep it that way. Never
paste it into chat tools, issues, or commit messages. If a key has ever left
this machine, rotate it.
