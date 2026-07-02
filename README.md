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
- [Flag reference](#flag-reference)
- [Scope files](#scope-files--x---i)
- [Incremental scans](#incremental-scans)
- [Methodology](#methodology-what-each-phase-does)
- [Output layout](#output-layout)
- [Architecture](#architecture-notes)
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
```

## Flag reference

| Flag | Description |
|---|---|
| `-d <domain>` | Scan a single domain |
| `-l <file>` | Scan multiple domains, one per line |
| `-t <tools>` | Only run these sources (comma separated) |
| `-e <tools>` | Exclude these sources (comma separated) |
| `-x <file>` | Out-of-scope file — drop matching subdomains |
| `-i <file>` | Include-only file — restrict to matching subdomains |
| `-b` | DNS permutation (dnsgen/alterx/shuffledns) + wordlist bruteforce (puredns) |
| `-p` | Passive port discovery (`naabu -passive`) |
| `-o` | Origin IP discovery behind WAF/CDN |
| `-j <n>` | Max concurrent tool jobs (default 8) |
| `-c` | Report available tools/keys, then exit |
| `-h` | Usage |

## Scope files (`-x` / `-i`)

One entry per line, `#` for comments:

```
example.com          # exact match
*.dev.example.com     # wildcard - base domain and any subdomain of it
```

`-i` (include) is applied first as a whitelist, `-x` (exclude/OOS) after.
Both re-apply following the bruteforce/permutation phase, since that phase
can generate names outside your intended scope.

## Incremental scans

If a previous `results/<domain>_*` run exists, RecoGun automatically diffs
against the most recent one and reports `new_subdomains.txt`,
`new_active_subdomains.txt`, and `crawling/new_urls.txt` — the actual new
attack surface since last time, not the full list again. No flag needed;
just re-run the same domain periodically, e.g. from cron:

```bash
0 */6 * * * cd /path/to/RecoGun && ./recogun.sh -d target.com >> cron.log 2>&1
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
8. **Crawling** (parallel) — waymore, waybackurls, gau, katana; merged,
   diffed, deduped with `uro`, split into JS files and API-shaped endpoints.
   If `paramx` is installed, parameterized URLs are tagged by likely vuln
   class for triage — classification only, no payloads sent.
9. **Report** — `report.txt` (human) and `report.json` (machine-readable).

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
