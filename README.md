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
> permission is on you, not the tool. Respect program scope (`-x`/`-i` exist
> for exactly this) and rate limits.

## Table of contents

- [Features](#features)
- [Quick start](#quick-start)
- [Methodology](#methodology-what-each-phase-does)
- [Flag reference](#flag-reference)
- [Bundled defaults](#bundled-defaults-wordlists--resolvers)
- [Feature guides](#feature-guides)
  - [Scope files (`-x`/`-i`)](#scope-files--x---i)
  - [Incremental scans](#incremental-scans)
  - [Multi-domain progress (`-l`)](#multi-domain-progress--l)
  - [Auto-update check (`-u`)](#auto-update-check--u)
- [Output layout](#output-layout)
- [Troubleshooting](#troubleshooting)
- [Architecture notes](#architecture-notes)
- [Credential hygiene](#credential-hygiene)

## Features

- **20+ passive subdomain sources** — subfinder, assetfinder, findomain,
  amass, crt.sh, certspotter, AlienVault OTX, subdomain.center, bufferover,
  AbuseIPDB, and key-gated sources (chaos, shosubgo, censys, virustotal,
  github/gitlab-subdomains, haktrails) that auto-skip when no key is set.
- **Origin IP discovery (`-o`)** — find what's actually behind Cloudflare/
  Akamai/etc. via cert search, historical DNS, favicon hashing, and
  multi-engine lookup (`uncover`), then confirm candidates with a direct
  request — no exploitation, just fingerprinting.
- **Scope-aware** — `-x`/`-i` files keep every phase inside a program's
  actual scope, including after DNS permutation (which can otherwise wander
  outside it).
- **Incremental by default** — every run diffs subdomains, active hosts, and
  crawled URLs against the last run for the same domain. No flag needed.
- **Self-contained** — a default wordlist, resolvers list, and permutation
  wordlist all ship in the repo, so `-b` works right after cloning.
- **Parallel execution** — passive enumeration, crawling, and resolver
  validation all run concurrently with a configurable job cap (`-j`).
- **Fail-soft** — a missing tool or a dead API key never kills the run; it's
  logged and skipped. `-c` gives you a full dependency/key report up front.
- **Structured output** — `report.txt` for humans, `report.json` for
  pipelines/dashboards.

## Quick start

```bash
git clone <this-repo>
cd RecoGun
cp config.env.example config.env   # fill in whichever API keys you have
chmod +x recogun.sh
./recogun.sh -c                    # see what's actually available
./recogun.sh -d target.com
./recogun.sh -d target.com -b      # bruteforce works immediately - see "Bundled defaults" below
```

## Methodology (what each phase does)

1. **Passive subdomain enumeration** (parallel, capped by `-j`) — merged,
   deduped, and scope-filtered.
2. **Origin IP discovery** (`-o`, opt-in) — domain-level, runs once, not per
   subdomain. `wafw00f` fingerprints the WAF/CDN; candidate IPs come from
   VirusTotal historical resolutions, AlienVault OTX, URLScan.io, a Shodan
   `ssl.cert.subject.CN` search, `uncover`, and Shodan favicon-hash search.
   Each candidate gets a direct GET (`curl --resolve`, Host header spoofed)
   compared against the normal response's status + `<title>` — a heuristic,
   not proof; matches land in `verified_origin_ips.txt` for manual
   confirmation.
3. **Permutation + bruteforce** (`-b`, opt-in) — resolvers validated first
   (dead ones dropped); dnsgen/alterx permutate *from subdomains already
   found*, resolved via shuffledns; puredns bruteforces a wordlist
   separately; dnsrecon runs standard enumeration. Re-merged, re-filtered.
4. **New-subdomains diff** against the previous run, if any.
5. **HTTP probing** — httpx confirms live hosts, diffed against last run.
6. **Passive port discovery** (`-p`, opt-in) — `naabu -passive`, no direct
   scanning of the target.
7. **Takeover check** — subzy against live subdomains.
8. **Crawling** (parallel, **opt-in with `-C`** — off by default) — waymore,
   waybackurls, gau, katana; merged, diffed, deduped with `uro`, split into
   JS files and API-shaped endpoints. If `paramx` is installed, parameterized
   URLs are tagged by likely vuln class for triage — classification only, no
   payloads sent. Once enabled, `-t`/`-e` apply here too (by tool name:
   `waymore`, `waybackurls`, `gau-crawl`, `katana`), so `-C -e katana` crawls
   with everything but katana.
9. **Report** — `report.txt` (human) and `report.json` (machine-readable).

## Flag reference

| Flag | Description |
|---|---|
| `-d <domain>` | Scan a single domain |
| `-l <file>` | Scan multiple domains, one per line |
| `-t <tools>` | Only run these sources (comma separated) — covers passive-enum **and** crawling tool names |
| `-e <tools>` | Exclude these sources (comma separated) — e.g. `-e katana` skips just katana |
| `-C` | Enable the crawling phase (waymore/waybackurls/gau-crawl/katana) — off by default |
| `-x <file>` | Out-of-scope file — drop matching subdomains |
| `-i <file>` | Include-only file — restrict to matching subdomains |
| `-b` | DNS permutation (dnsgen/alterx/shuffledns) + wordlist bruteforce (puredns) |
| `-w <file>` | Custom wordlist for `-b` (default: bundled `wordlists/subdomains.txt`) |
| `-r <file>` | Custom resolvers for `-b` (default: bundled `resolvers.txt`) |
| `-m <file>` | Custom permutation wordlist for `-b` (default: bundled `wordlists/permutations.txt`) |
| `-p` | Passive port discovery (`naabu -passive`) |
| `-o` | Origin IP discovery behind WAF/CDN |
| `-j <n>` | Max concurrent tool jobs (default 8) |
| `-v` | Verbose — log the actual command run per tool (API keys redacted) |
| `-c` | Report available tools/keys, then exit |
| `-u` | Check for a newer RecoGun version now, then exit |
| `-h` | Usage |

Every run prints a config summary (target, which optional phases are on,
scope files, parallel jobs) before scanning starts — so you always know
exactly what a given invocation is about to do without re-reading flags.

## Bundled defaults (wordlists & resolvers)

Three files ship in the repo so `-b` is usable straight after cloning, with
no extra downloads:

- `resolvers.txt` — 21 major public resolvers
- `wordlists/subdomains.txt` — SecLists' `subdomains-top1million-5000` (5,000 entries), used by `puredns` for wordlist bruteforce
- `wordlists/permutations.txt` — [six2dez/OneListForAll](https://github.com/six2dez/OneListForAll)'s `permutations_short.txt` (1,069 entries — `dev`, `staging`, `api`, `www1`-`www7`, etc.), used by `dnsgen -w` and (only if you pass `-m`) `alterx -pp word=`

All three resolve relative to the script's own location, not your current
directory, so this works no matter where you run RecoGun from. Pass
`-w`/`-r`/`-m` to use your own instead; nothing needs to change in the repo.

**Note on `-m`:** without it, `alterx` runs with `-en` (enrichment — *adds*
words pulled from your already-found subdomains on top of its own curated
list). `alterx`'s built-in word list is purpose-built for its DSL patterns,
so RecoGun doesn't silently swap it out for a generic wordlist — `-m` only
takes effect for `alterx` if you explicitly pass it, in which case it
replaces alterx's `word` payload outright (`-pp word=<file>`).

## Feature guides

### Scope files (`-x` / `-i`)

One entry per line, `#` for comments:

```
example.com          # exact match
*.dev.example.com     # wildcard - base domain and any subdomain of it
```

`-i` (include) is applied first as a whitelist, `-x` (exclude/OOS) after.
Both re-apply following the bruteforce/permutation phase, since that phase
can generate names outside your intended scope.

### Incremental scans

If a previous `results/<domain>_*` run exists, RecoGun automatically diffs
against the most recent one and reports `new_subdomains.txt`,
`new_active_subdomains.txt`, and `crawling/new_urls.txt` — the actual new
attack surface since last time, not the full list again. No flag needed;
just re-run the same domain periodically, e.g. from cron:

```bash
0 */6 * * * cd /path/to/RecoGun && ./recogun.sh -d target.com >> cron.log 2>&1
```

### Multi-domain progress (`-l`)

Each domain in the list gets a `[N/Total]` prefix on its start/summary/done
lines, so a long list running unattended shows exactly where it is:

```
[3/10] [*] Processing domain: example.com
[3/10] === SCAN SUMMARY: example.com ===
[3/10] [DONE] example.com
```

After the whole list finishes, a final banner reports which domains (if
any) had takeovers or tool errors, across the entire run:

```
  +=========================================+
  |   ALL 10 DOMAIN(S) COMPLETE
  +=========================================+
Takeovers found on: example.com internal.example.com
```

### Auto-update check (`-u`)

Every run auto-checks for updates (`git fetch`, 10s timeout) before
scanning. In a real terminal, it asks `[y/N]` before pulling; in a
non-interactive session (cron, CI) it never prompts — it just logs that an
update exists and continues with the current version, so automated runs
can never hang waiting on stdin that will never arrive. `git pull` on
"yes" then exits rather than trying to hot-swap the running script. Run
`-u` on its own to check on demand, with explicit feedback either way.

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
├── naabu.txt                  (-p)
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

### `-b` takes 24h on one domain, httpx never finishes

This is wildcard DNS, not a performance bug. If `*.domain.tld` resolves to
*something* for any subdomain you query, every single wordlist/permutation
guess in the bruteforce phase "succeeds" as a false positive — the candidate
list explodes to the size of your wordlist, and `httpx` then has to probe
all of it one by one. RecoGun checks for this automatically before running
`-b`: two random, near-certainly-nonexistent subdomains are resolved, and if
both answer, the whole permutation/bruteforce phase is skipped for that
domain with a loud warning instead of silently producing garbage. `httpx`
itself also runs with explicit concurrency (`HTTPX_THREADS`, default 100)
and a 5s per-host timeout, and logs a warning if more than 20,000
subdomains get queued for probing regardless of cause.

## Architecture notes

- All error tracking goes through a per-run file (`.tool_errors`) rather
  than an in-memory array, so it stays correct when tools run in parallel.
- `run_tools_parallel` takes an array of `"name:command"` pairs and a target
  directory, fanning them out with a `PARALLEL_JOBS` concurrency cap
  (default 8, override with `-j` or `PARALLEL_JOBS` in `config.env`).
- Fixed from earlier versions: the old `-br` bruteforce flag never triggered
  (`getopts` only returns single characters, so `br)` was dead code — now
  `-b`). Permutation tooling used to run *before* the first subdomain merge,
  so it had nothing to permutate — it now runs after. Per-tool logs used to
  split across `sources/`, `bruteforce/`, `crawling/` subdirs instead of one
  log — now unified into a single `recogun.log` per run.

## Credential hygiene

`config.env` holds live API keys — it's gitignored, keep it that way. Never
paste it into chat tools, issues, or commit messages. If a key has ever left
this machine, rotate it.
