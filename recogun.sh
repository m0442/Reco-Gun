#!/bin/bash
# ------------------------------------------------------------------------------
# RecoGun - An Advanced Automated Reconnaissance Tool
#
# Author: M0442
# GitHub: https://github.com/m0442
#
# Description:
# Automates passive/semi-passive subdomain enumeration, resolution,
# HTTP probing, takeover checks, and crawling for bug bounty / pentest
# recon. Aggregates results from many sources, dedupes, and produces a
# per-target report. No active vulnerability testing is performed here
# by design - this tool only maps attack surface.
# ------------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/config.env" ]; then
    source "$SCRIPT_DIR/config.env"
else
    echo -e "\033[31mError: config.env not found next to recogun.sh. Copy config.env.example to config.env and fill in your keys.\033[0m"
    exit 1
fi

# Variables
DOMAIN=""
DOMAINS_FILE=""
OOS_FILE=""
INCLUDE_FILE=""
OUTPUT_DIR="results"
TOOLS_TO_RUN=()
TOOLS_TO_EXCLUDE=()
BRUTEFORCE=false
PORT_DISCOVERY=false
ORIGIN_IP_DISCOVERY=false
VERBOSE=false
RESOLVERS_FILE="${RESOLVERS_FILE:-resolvers.txt}"
WORDLISTS_DIR="${WORDLISTS_DIR:-wordlists}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-300}"
CRAWL_TIMEOUT_SECONDS="${CRAWL_TIMEOUT_SECONDS:-1800}"
PARALLEL_JOBS="${PARALLEL_JOBS:-8}"
HTTPX_THREADS="${HTTPX_THREADS:-100}"
ACTIVE_SUBDOMAINS=""
CURRENT_LOG=""
CURRENT_ERRORS=""
PREV_DIR=""

# Colors
GREEN='\033[32m'
RED='\033[31m'
BLUE='\033[34m'
YELLOW='\033[33m'
PURPLE='\033[35m'
CYAN='\033[36m'
RESET='\033[0m'

log_message() {
    local message="$1"
    local color="$2"
    echo -e "${color}$(date '+%Y-%m-%d %H:%M:%S') - ${message}${RESET}"
}

count_unique_results() {
    local file="$1"
    if [ -f "$file" ] && [ -s "$file" ]; then
        sort -u "$file" | wc -l
    else
        echo 0
    fi
}

# Mask configured API key values in a command string before it's ever
# logged/printed - several tool invocations embed keys directly
# (chaos -key $CHAOS_API_KEY, github-subdomains -t $GITHUB_TOKEN, etc.) and
# recogun.log/-v output must never become a second place those keys live.
redact_command() {
    local cmd="$1"
    for key_var in CHAOS_API_KEY SHODAN_API_KEY CENSYS_API_KEY VIRUSTOTAL_API_KEY \
                   GITHUB_TOKEN GITLAB_TOKEN; do
        local val="${!key_var}"
        [[ -n "$val" ]] && cmd="${cmd//$val/***REDACTED***}"
    done
    echo "$cmd"
}

# Run a tool, capture its output, log the result. Errors go to a file
# (not an in-memory array) so this stays safe to call from parallel
# subshells. Never lets one bad tool kill the run.
run_tool() {
    local tool_name="$1"
    local command="$2"
    local output_file="$3"
    local tool_timeout="${4:-$TIMEOUT_SECONDS}"

    log_message "[+] Running $tool_name..." "$BLUE"
    $VERBOSE && log_message "    -> $(redact_command "$command")" "$CYAN"
    if timeout "$tool_timeout" bash -c "$command" > "$output_file" 2>> "$CURRENT_LOG"; then
        if [ -s "$output_file" ]; then
            local count
            count=$(count_unique_results "$output_file")
            log_message "[OK] $tool_name completed. Found $count results" "$GREEN"
        else
            log_message "[!] $tool_name completed but no results found." "$YELLOW"
        fi
    else
        log_message "[X] Error in $tool_name. Skipping to the next tool..." "$RED"
        echo "$tool_name" >> "$CURRENT_ERRORS"
        rm -f "$output_file"
        return 1
    fi
}

# Run an array of "name:command" pairs concurrently, capped at PARALLEL_JOBS.
# Optional 3rd arg overrides the per-tool timeout (default: TIMEOUT_SECONDS).
run_tools_parallel() {
    local -n tools_ref="$1"
    local output_dir="$2"
    local job_timeout="${3:-$TIMEOUT_SECONDS}"

    for tool in "${tools_ref[@]}"; do
        local tool_name="${tool%%:*}"
        local tool_command="${tool#*:}"
        run_tool "$tool_name" "$tool_command" "$output_dir/${tool_name}.txt" "$job_timeout" &
        while [ "$(jobs -r -p | wc -l)" -ge "$PARALLEL_JOBS" ]; do
            wait -n
        done
    done
    wait
}

merge_results() {
    local dir="$1"
    local dest="$2"
    cat "$dir"/*.txt 2>/dev/null | sed '/^\s*$/d' | sort -u > "$dest"
}

# Convert a scope file (exact entries or *.domain wildcards) into a regex
# file usable with grep -Ef / grep -vEf.
build_scope_regex_file() {
    local src="$1"
    local dest="$2"
    > "$dest"
    while IFS= read -r line || [[ -n "$line" ]]; do
        line=$(echo "$line" | xargs)
        [[ -z "$line" || "$line" == \#* ]] && continue
        if [[ "$line" == \*.* ]]; then
            local base="${line#\*.}"
            local base_escaped
            base_escaped=$(echo "$base" | sed 's/\./\\./g')
            echo "(^|\\.)${base_escaped}\$" >> "$dest"
        else
            local escaped
            escaped=$(echo "$line" | sed 's/\./\\./g')
            echo "^${escaped}\$" >> "$dest"
        fi
    done < "$src"
}

# Apply -i (include-only whitelist) then -x (out-of-scope exclusion) to a
# subdomain list, in place.
apply_scope_filters() {
    local target_file="$1"
    local work_dir="$2"

    if [[ -n "$INCLUDE_FILE" ]]; then
        local include_regex="$work_dir/.include_regex.txt"
        build_scope_regex_file "$INCLUDE_FILE" "$include_regex"
        if [ -s "$include_regex" ] && [ -s "$target_file" ]; then
            grep -Ef "$include_regex" "$target_file" > "$target_file.tmp" 2>/dev/null
            mv "$target_file.tmp" "$target_file"
            log_message "[i] Include-scope filter applied: $(count_unique_results "$target_file") remain" "$YELLOW"
        fi
    fi

    if [[ -n "$OOS_FILE" ]]; then
        local oos_regex="$work_dir/.oos_regex.txt"
        build_scope_regex_file "$OOS_FILE" "$oos_regex"
        if [ -s "$oos_regex" ] && [ -s "$target_file" ]; then
            grep -vEf "$oos_regex" "$target_file" > "$target_file.tmp" 2>/dev/null
            mv "$target_file.tmp" "$target_file"
            log_message "[i] Out-of-scope exclusion applied: $(count_unique_results "$target_file") remain" "$YELLOW"
        fi
    fi
}

# Most recent prior results dir for this domain, excluding the one we're
# writing to right now.
find_previous_run_dir() {
    local domain="$1"
    local current_dir="$2"
    find "$OUTPUT_DIR" -maxdepth 1 -type d -name "${domain}_*" 2>/dev/null \
        | grep -vF "$current_dir" | sort | tail -1
}

diff_against_previous() {
    local prev_file="$1"
    local curr_file="$2"
    local out_file="$3"
    local label="$4"

    if [[ -n "$PREV_DIR" && -f "$prev_file" && -s "$curr_file" ]]; then
        comm -13 <(sort -u "$prev_file") <(sort -u "$curr_file") > "$out_file"
        log_message "[i] New $label since last scan: $(count_unique_results "$out_file")" "$CYAN"
    fi
}

# Detect wildcard DNS: if two random, near-certainly-nonexistent subdomains
# both resolve, every bruteforce/permutation guess would "succeed" as a false
# positive and explode the candidate list (then httpx has to probe all of
# it). Bruteforce/permutation is pointless and actively harmful here.
has_wildcard_dns() {
    local domain="$1"
    if ! command -v dig &>/dev/null; then
        return 1
    fi
    local test1 test2
    test1=$(dig +short "rg-wc-check-${RANDOM}${RANDOM}.${domain}" A 2>/dev/null)
    test2=$(dig +short "rg-wc-check-${RANDOM}${RANDOM}.${domain}" A 2>/dev/null)
    [[ -n "$test1" && -n "$test2" ]]
}

# Filter resolvers.txt down to resolvers that actually answer a query,
# in parallel. A stale resolvers file silently poisons bruteforce results.
validate_resolvers() {
    local src="$1"
    local dest="$2"

    if ! command -v dig &>/dev/null; then
        log_message "[!] dig not found - skipping resolver validation, using list as-is" "$YELLOW"
        cp "$src" "$dest"
        return
    fi

    log_message "[*] Validating resolvers in $src..." "$BLUE"
    local tmp_dir
    tmp_dir=$(mktemp -d)
    local total=0

    while IFS= read -r resolver || [[ -n "$resolver" ]]; do
        resolver=$(echo "$resolver" | xargs)
        [[ -z "$resolver" || "$resolver" == \#* ]] && continue
        total=$((total + 1))
        (
            if dig +time=2 +tries=1 "@$resolver" google.com A +short 2>/dev/null | grep -qE '^[0-9]+\.'; then
                echo "$resolver" >> "$tmp_dir/valid.txt"
            fi
        ) &
        while [ "$(jobs -r -p | wc -l)" -ge "$PARALLEL_JOBS" ]; do
            wait -n
        done
    done < "$src"
    wait

    if [ -f "$tmp_dir/valid.txt" ]; then
        sort -u "$tmp_dir/valid.txt" > "$dest"
    else
        > "$dest"
    fi
    rm -rf "$tmp_dir"
    log_message "[OK] Resolvers: $(count_unique_results "$dest")/$total responsive" "$GREEN"
}

export_json() {
    local domain="$1"
    local domain_output_dir="$2"
    local final_output="$3"

    if ! command -v jq &>/dev/null; then
        log_message "[!] jq not found - skipping report.json export" "$YELLOW"
        return
    fi

    local tool_errors_json="[]"
    if [ -s "$CURRENT_ERRORS" ]; then
        tool_errors_json=$(jq -R -s -c 'split("\n") | map(select(length > 0))' < "$CURRENT_ERRORS")
    fi

    local takeover_bool="false"
    [ -s "$domain_output_dir/takeovers.txt" ] && takeover_bool="true"

    jq -n \
        --arg domain "$domain" \
        --arg timestamp "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
        --argjson total_subdomains "$(count_unique_results "$final_output")" \
        --argjson active_subdomains "$(count_unique_results "$ACTIVE_SUBDOMAINS")" \
        --argjson new_subdomains "$(count_unique_results "$domain_output_dir/new_subdomains.txt")" \
        --argjson new_active_subdomains "$(count_unique_results "$domain_output_dir/new_active_subdomains.txt")" \
        --argjson urls_found "$(count_unique_results "$domain_output_dir/crawling/final_crawling_results.txt")" \
        --argjson new_urls "$(count_unique_results "$domain_output_dir/crawling/new_urls.txt")" \
        --argjson js_files "$(count_unique_results "$domain_output_dir/crawling/javascript_files.txt")" \
        --argjson api_endpoints "$(count_unique_results "$domain_output_dir/crawling/api_endpoints.txt")" \
        --argjson subdomain_takeover_found "$takeover_bool" \
        --argjson origin_ip_candidates "$(count_unique_results "$domain_output_dir/origin_ip/candidate_ips.txt")" \
        --argjson origin_ip_verified "$(count_unique_results "$domain_output_dir/origin_ip/verified_origin_ips.txt")" \
        --argjson tool_errors "$tool_errors_json" \
        --arg final_subdomains_file "$final_output" \
        --arg active_subdomains_file "$ACTIVE_SUBDOMAINS" \
        --arg crawling_dir "$domain_output_dir/crawling" \
        '{
            domain: $domain,
            timestamp: $timestamp,
            results: {
                total_subdomains: $total_subdomains,
                active_subdomains: $active_subdomains,
                new_subdomains_since_last_scan: $new_subdomains,
                new_active_subdomains_since_last_scan: $new_active_subdomains,
                urls_found: $urls_found,
                new_urls_since_last_scan: $new_urls,
                javascript_files: $js_files,
                api_endpoints: $api_endpoints,
                subdomain_takeover_found: $subdomain_takeover_found,
                origin_ip_candidates: $origin_ip_candidates,
                origin_ip_verified: $origin_ip_verified
            },
            tool_errors: $tool_errors,
            files: {
                final_subdomains: $final_subdomains_file,
                active_subdomains: $active_subdomains_file,
                crawling_dir: $crawling_dir
            }
        }' > "$domain_output_dir/report.json"

    log_message "[OK] JSON report saved to $domain_output_dir/report.json" "$GREEN"
}

# Hash the default favicon the way Shodan does (mmh3 of base64) and search
# for other hosts serving the same one. Only checks /favicon.ico - sites
# that reference their icon elsewhere need this done manually.
run_favicon_hash_search() {
    local domain="$1"
    local out_dir="$2"

    if ! command -v python3 &>/dev/null || ! python3 -c "import mmh3" &>/dev/null 2>&1; then
        log_message "[!] python3/mmh3 not available - skipping favicon hash search (pip install mmh3)" "$YELLOW"
        return
    fi
    if [[ -z "$SHODAN_API_KEY" ]] || ! command -v shodan &>/dev/null; then
        log_message "[!] shodan CLI/key not available - skipping favicon hash search" "$YELLOW"
        return
    fi

    local hash
    hash=$(python3 -c "
import sys, base64, mmh3, urllib.request
try:
    req = urllib.request.Request(sys.argv[1], headers={'User-Agent': 'Mozilla/5.0'})
    data = urllib.request.urlopen(req, timeout=10).read()
    print(mmh3.hash(base64.encodebytes(data)))
except Exception:
    pass
" "https://$domain/favicon.ico" 2>>"$CURRENT_LOG")

    if [[ -z "$hash" ]]; then
        log_message "[!] Could not fetch/hash favicon at https://$domain/favicon.ico" "$YELLOW"
        return
    fi

    log_message "[i] Favicon hash: $hash - searching Shodan..." "$BLUE"
    run_tool "favicon-hash" "shodan search --fields ip_str http.favicon.hash:$hash | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}'" "$out_dir/favicon_hash.txt"
}

# For each candidate IP, request the domain directly (bypassing DNS/CDN) and
# compare HTTP status + <title> against the normal WAF-fronted response.
# Heuristic, not proof - matches get flagged for manual confirmation.
verify_origin_candidates() {
    local domain="$1"
    local candidates_file="$2"
    local out_dir="$3"

    if [ ! -s "$candidates_file" ]; then
        log_message "[!] No origin IP candidates to verify" "$YELLOW"
        return
    fi

    log_message "[*] Verifying $(count_unique_results "$candidates_file") candidate IPs against $domain..." "$BLUE"

    local baseline_status baseline_title baseline_sig
    baseline_status=$(curl -sk --max-time 10 -o /tmp/rg_baseline_$$.html -w '%{http_code}' "https://$domain/" 2>>"$CURRENT_LOG")
    baseline_title=$(sed -n 's/.*<[Tt][Ii][Tt][Ll][Ee]>\(.*\)<\/[Tt][Ii][Tt][Ll][Ee]>.*/\1/p' /tmp/rg_baseline_$$.html 2>/dev/null | head -1 | xargs)
    rm -f /tmp/rg_baseline_$$.html
    baseline_sig="${baseline_status}|${baseline_title}"

    > "$out_dir/verified_origin_ips.txt"
    while IFS= read -r ip || [[ -n "$ip" ]]; do
        [[ -z "$ip" ]] && continue
        (
            local status title sig tmpfile
            tmpfile="/tmp/rg_candidate_$$_${ip//./_}.html"
            status=$(curl -sk --max-time 10 --resolve "$domain:443:$ip" -o "$tmpfile" -w '%{http_code}' "https://$domain/" 2>>"$CURRENT_LOG")
            title=$(sed -n 's/.*<[Tt][Ii][Tt][Ll][Ee]>\(.*\)<\/[Tt][Ii][Tt][Ll][Ee]>.*/\1/p' "$tmpfile" 2>/dev/null | head -1 | xargs)
            rm -f "$tmpfile"
            sig="${status}|${title}"
            if [[ -n "$title" && "$sig" == "$baseline_sig" ]]; then
                echo "$ip" >> "$out_dir/verified_origin_ips.txt"
            fi
        ) &
        while [ "$(jobs -r -p | wc -l)" -ge "$PARALLEL_JOBS" ]; do
            wait -n
        done
    done < "$candidates_file"
    wait

    if [ -s "$out_dir/verified_origin_ips.txt" ]; then
        log_message "[OK] Verified origin IP(s): $(count_unique_results "$out_dir/verified_origin_ips.txt")" "$GREEN"
    else
        log_message "[!] No candidate matched the baseline exactly - manually check candidate_ips.txt (WAF may still be blocking direct access)" "$YELLOW"
    fi
}

process_domain() {
    local domain="$1"
    local timestamp
    timestamp=$(date '+%Y%m%d_%H%M%S')
    local domain_output_dir="$OUTPUT_DIR/${domain}_${timestamp}"
    mkdir -p "$domain_output_dir/sources" "$domain_output_dir/bruteforce" "$domain_output_dir/crawling"
    local final_output="$domain_output_dir/final_subdomains.txt"
    ACTIVE_SUBDOMAINS="$domain_output_dir/active_subdomains.txt"
    CURRENT_LOG="$domain_output_dir/recogun.log"
    CURRENT_ERRORS="$domain_output_dir/.tool_errors"
    > "$CURRENT_LOG"
    > "$CURRENT_ERRORS"

    log_message "[*] Processing domain: $domain" "$PURPLE"

    PREV_DIR=$(find_previous_run_dir "$domain" "$domain_output_dir")
    if [[ -n "$PREV_DIR" ]]; then
        log_message "[i] Comparing against previous scan: $PREV_DIR" "$CYAN"
    else
        log_message "[i] No previous scan found for $domain - this is the baseline run" "$YELLOW"
    fi

    # ---- Phase 1: passive subdomain enumeration (parallel) ----
    local TOOLS=(
        "subfinder:subfinder -all -silent -d $domain"
        "assetfinder:assetfinder --subs-only $domain"
        "findomain:findomain -t $domain -q"
        "amass:amass enum -passive -d $domain"
        "cero:cero $domain"
        "sublist3r:sublist3r -d $domain"
        "gau:gau --threads 5 --subs $domain | unfurl -u domains"
        "crtsh:curl -s 'https://crt.sh/?q=%25.$domain&output=json' | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u"
        "certspotter:curl -sk 'https://api.certspotter.com/v1/issuances?domain=$domain&include_subdomains=true&expand=dns_names' | jq -r '.[].dns_names[]' | sort -u"
        "alienvault:curl -s 'https://otx.alienvault.com/api/v1/indicators/domain/$domain/passive_dns' | jq -r '.passive_dns[].hostname' | sort -u"
        "subdomain-center:curl -s 'https://api.subdomain.center/?domain=$domain' | jq -r '.[]'"
        "bufferover:curl -s 'https://dns.bufferover.run/dns?q=.$domain' | jq -r '.FDNS_A[]? // empty' | sed 's/.*,//' | sort -u"
        "abuseipdb:curl -s 'https://www.abuseipdb.com/whois/$domain' -H 'user-agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36' | grep -E '<li>\w.*</li>' | sed -E 's/<\/?li>//g' | sed -e \"s/\$/.$domain/\" | sort -u"
    )

    [[ -n "$CHAOS_API_KEY" ]] && TOOLS+=("chaos:chaos -silent -key $CHAOS_API_KEY -d $domain") \
        || log_message "[i] Skipping chaos - CHAOS_API_KEY not set" "$YELLOW"
    [[ -n "$SHODAN_API_KEY" ]] && TOOLS+=("shosubgo:shosubgo -d $domain -s $SHODAN_API_KEY") \
        || log_message "[i] Skipping shosubgo - SHODAN_API_KEY not set" "$YELLOW"
    [[ -n "$CENSYS_API_KEY" ]] && TOOLS+=("censys:censys subdomains $domain | sed 's/^[ \t]*-//; s/-//g'") \
        || log_message "[i] Skipping censys - CENSYS_API_KEY not set" "$YELLOW"
    [[ -n "$VIRUSTOTAL_API_KEY" ]] && TOOLS+=("virustotal:curl -s 'https://www.virustotal.com/vtapi/v2/domain/report?apikey=$VIRUSTOTAL_API_KEY&domain=$domain' | jq -r '.subdomains[]?'") \
        || log_message "[i] Skipping virustotal - VIRUSTOTAL_API_KEY not set" "$YELLOW"
    [[ -n "$GITHUB_TOKEN" ]] && TOOLS+=("github-subdomains:github-subdomains -d $domain -t $GITHUB_TOKEN -raw") \
        || log_message "[i] Skipping github-subdomains - GITHUB_TOKEN not set" "$YELLOW"
    [[ -n "$GITLAB_TOKEN" ]] && TOOLS+=("gitlab-subdomains:gitlab-subdomains -d $domain -t $GITLAB_TOKEN") \
        || log_message "[i] Skipping gitlab-subdomains - GITLAB_TOKEN not set" "$YELLOW"
    command -v haktrails &>/dev/null && TOOLS+=("haktrails:echo \"$domain\" | haktrails subdomains")

    local FILTERED_TOOLS=()
    for tool in "${TOOLS[@]}"; do
        local tool_name="${tool%%:*}"
        tool_name=$(echo "$tool_name" | xargs)

        if [[ ${#TOOLS_TO_RUN[@]} -gt 0 && ! " ${TOOLS_TO_RUN[*]} " =~ " ${tool_name} " ]]; then
            continue
        fi
        if [[ " ${TOOLS_TO_EXCLUDE[*]} " =~ " ${tool_name} " ]]; then
            log_message "[i] Excluding tool: $tool_name" "$YELLOW"
            continue
        fi
        FILTERED_TOOLS+=("$tool")
    done

    log_message "[*] Running ${#FILTERED_TOOLS[@]} passive sources (up to $PARALLEL_JOBS in parallel)..." "$BLUE"
    run_tools_parallel FILTERED_TOOLS "$domain_output_dir/sources"

    log_message "[+] Merging passive enumeration results..." "$BLUE"
    merge_results "$domain_output_dir/sources" "$final_output"
    apply_scope_filters "$final_output" "$domain_output_dir"
    log_message "[OK] Found $(count_unique_results "$final_output") unique subdomains from passive sources" "$GREEN"

    # ---- Phase 1b: origin IP discovery (opt-in, -o) ----
    # Domain-level, not per-subdomain - a CDN/WAF setup is usually org-wide.
    # Gathers candidate origin IPs from passive sources + favicon hashing,
    # then confirms candidates with a direct GET (Host header spoofed via
    # --resolve) compared against the normal WAF-fronted response. No
    # payloads sent - this is fingerprinting/confirmation, not exploitation.
    if $ORIGIN_IP_DISCOVERY; then
        log_message "[*] Running origin IP discovery for $domain..." "$BLUE"
        mkdir -p "$domain_output_dir/origin_ip"

        if command -v wafw00f &>/dev/null; then
            run_tool "wafw00f" "wafw00f https://$domain -a" "$domain_output_dir/origin_ip/waf_detection.txt"
        else
            log_message "[!] wafw00f not installed. Skipping WAF fingerprint." "$YELLOW"
        fi

        local ORIGIN_TOOLS=()
        if [[ -n "$VIRUSTOTAL_API_KEY" ]]; then
            ORIGIN_TOOLS+=("vt-resolutions:curl -s 'https://www.virustotal.com/vtapi/v2/domain/report?apikey=$VIRUSTOTAL_API_KEY&domain=$domain' | jq -r '.resolutions[]?.ip_address // empty'")
        fi
        ORIGIN_TOOLS+=("otx-ips:curl -s 'https://otx.alienvault.com/api/v1/indicators/hostname/$domain/url_list?limit=500&page=1' | jq -r '.url_list[]?.result?.urlworker?.ip // empty'")
        ORIGIN_TOOLS+=("urlscan-ips:curl -s 'https://urlscan.io/api/v1/search/?q=domain:$domain&size=10000' | jq -r '.results[]?.page?.ip // empty'")
        if [[ -n "$SHODAN_API_KEY" ]] && command -v shodan &>/dev/null; then
            ORIGIN_TOOLS+=("shodan-cert:shodan search --fields ip_str ssl.cert.subject.CN:$domain 200 | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}'")
        fi
        if command -v uncover &>/dev/null; then
            ORIGIN_TOOLS+=("uncover:echo $domain | uncover -e shodan,censys,fofa,quake,hunter,zoomeye,netlas,criminalip -silent | cut -d: -f1")
        fi

        run_tools_parallel ORIGIN_TOOLS "$domain_output_dir/origin_ip"
        run_favicon_hash_search "$domain" "$domain_output_dir/origin_ip"

        local candidate_ips="$domain_output_dir/origin_ip/candidate_ips.txt"
        cat "$domain_output_dir/origin_ip"/*.txt 2>/dev/null \
            | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u > "$candidate_ips"
        log_message "[OK] Found $(count_unique_results "$candidate_ips") candidate origin IPs" "$GREEN"

        verify_origin_candidates "$domain" "$candidate_ips" "$domain_output_dir/origin_ip"
    fi

    # ---- Phase 2: permutation + bruteforce (opt-in, -b) ----
    if $BRUTEFORCE && has_wildcard_dns "$domain"; then
        log_message "[!] Wildcard DNS detected on $domain - every bruteforce/permutation guess would resolve as a false positive (this is what causes 100k+ fake 'subdomains' and multi-hour httpx runs). Skipping bruteforce/permutation entirely for this domain." "$RED"
    elif $BRUTEFORCE; then
        local resolvers_valid="$RESOLVERS_FILE"
        if [ -f "$RESOLVERS_FILE" ]; then
            resolvers_valid="$domain_output_dir/bruteforce/resolvers_valid.txt"
            validate_resolvers "$RESOLVERS_FILE" "$resolvers_valid"
        fi

        if [ ! -s "$final_output" ]; then
            log_message "[!] No seed subdomains for permutation - skipping dnsgen/alterx" "$YELLOW"
        else
            local PERM_TOOLS=()
            command -v dnsgen &>/dev/null && PERM_TOOLS+=("dnsgen:dnsgen $final_output")
            command -v alterx &>/dev/null && PERM_TOOLS+=("alterx:alterx -l $final_output")
            if [ ${#PERM_TOOLS[@]} -gt 0 ]; then
                run_tools_parallel PERM_TOOLS "$domain_output_dir/bruteforce"
            fi

            local permutations_combined="$domain_output_dir/bruteforce/permutations_combined.txt"
            cat "$domain_output_dir/bruteforce/dnsgen.txt" "$domain_output_dir/bruteforce/alterx.txt" 2>/dev/null \
                | sed '/^\s*$/d' | sort -u > "$permutations_combined"

            if [ -s "$permutations_combined" ] && [ -s "$resolvers_valid" ] && command -v shuffledns &>/dev/null; then
                run_tool "shuffledns-resolve" "shuffledns -d $domain -list $permutations_combined -r $resolvers_valid -mode resolve -silent" \
                    "$domain_output_dir/bruteforce/shuffledns_resolved.txt"
            elif [ -s "$permutations_combined" ]; then
                log_message "[!] shuffledns or validated resolvers not available - permutations generated but not resolved" "$YELLOW"
            fi
        fi

        local WORDLIST_TOOLS=()
        if [ -s "$resolvers_valid" ] && [ -s "$WORDLISTS_DIR/subdomains.txt" ] && command -v puredns &>/dev/null; then
            WORDLIST_TOOLS+=("puredns:puredns bruteforce $WORDLISTS_DIR/subdomains.txt $domain --resolvers $resolvers_valid -q")
        else
            log_message "[!] Validated resolvers or wordlists/subdomains.txt not found - skipping wordlist bruteforce" "$YELLOW"
        fi
        command -v dnsrecon &>/dev/null && WORDLIST_TOOLS+=("dnsrecon:dnsrecon -d $domain")
        if [ ${#WORDLIST_TOOLS[@]} -gt 0 ]; then
            run_tools_parallel WORDLIST_TOOLS "$domain_output_dir/bruteforce"
        fi

        log_message "[+] Re-merging with bruteforce/permutation results..." "$BLUE"
        cat "$domain_output_dir/sources"/*.txt "$domain_output_dir/bruteforce"/*.txt 2>/dev/null \
            | grep -oE '[a-zA-Z0-9._-]+\.'"$(echo "$domain" | sed 's/\./\\./g')" \
            | sort -u > "$final_output"
        apply_scope_filters "$final_output" "$domain_output_dir"
        log_message "[OK] Total after bruteforce/permutation: $(count_unique_results "$final_output") unique subdomains" "$GREEN"
    fi

    diff_against_previous "$PREV_DIR/final_subdomains.txt" "$final_output" "$domain_output_dir/new_subdomains.txt" "subdomains"

    # ---- Phase 3: HTTP probing ----
    if [ -s "$final_output" ]; then
        local sub_count
        sub_count=$(count_unique_results "$final_output")
        if [ "$sub_count" -gt 20000 ]; then
            log_message "[!] $sub_count subdomains queued for HTTP probing - this is a lot and may take a long time. If this number looks implausibly high, check for wildcard DNS or narrow scope with -x/-i." "$YELLOW"
        fi
        log_message "[*] Running httpx..." "$BLUE"
        if command -v httpx &>/dev/null; then
            httpx -l "$final_output" -silent -threads "$HTTPX_THREADS" -timeout 5 -o "$ACTIVE_SUBDOMAINS" 2>> "$CURRENT_LOG"
            if [ -s "$ACTIVE_SUBDOMAINS" ]; then
                log_message "[+] Found $(count_unique_results "$ACTIVE_SUBDOMAINS") active subdomains" "$GREEN"
            else
                log_message "[!] No active subdomains found" "$YELLOW"
            fi
        else
            log_message "[!] httpx not installed. Skipping HTTP probing." "$YELLOW"
        fi
    else
        log_message "[!] No subdomains found to probe" "$YELLOW"
    fi

    diff_against_previous "$PREV_DIR/active_subdomains.txt" "$ACTIVE_SUBDOMAINS" "$domain_output_dir/new_active_subdomains.txt" "active subdomains"

    # ---- Phase 4: passive port discovery (opt-in, -p) ----
    # naabu -passive uses passive sources (Shodan/Censys), it does not scan
    # the target directly - kept in scope as recon, not active testing.
    if $PORT_DISCOVERY && [ -s "$ACTIVE_SUBDOMAINS" ]; then
        if command -v naabu &>/dev/null; then
            run_tool "naabu" "naabu -list $ACTIVE_SUBDOMAINS -passive -ec -cdn -c 5 -rate 500 -verify -silent" \
                "$domain_output_dir/naabu.txt"
        else
            log_message "[!] naabu not installed. Skipping passive port discovery." "$YELLOW"
        fi
    fi

    # ---- Phase 5: subdomain takeover check ----
    if [ -s "$ACTIVE_SUBDOMAINS" ]; then
        log_message "[*] Running subzy for subdomain takeovers..." "$BLUE"
        if command -v subzy &>/dev/null; then
            subzy run --targets "$ACTIVE_SUBDOMAINS" --hide_fails > "$domain_output_dir/takeovers.txt" 2>> "$CURRENT_LOG"
            if [ -s "$domain_output_dir/takeovers.txt" ]; then
                log_message "[OK] Potential takeovers found! Check takeovers.txt" "$GREEN"
            else
                log_message "[!] No subdomain takeovers found." "$YELLOW"
                rm -f "$domain_output_dir/takeovers.txt"
            fi
        else
            log_message "[!] subzy not installed. Skipping takeover detection." "$YELLOW"
        fi
    fi

    # ---- Phase 6: crawling (parallel) ----
    if [ -s "$ACTIVE_SUBDOMAINS" ]; then
        log_message "[*] Running crawling tools..." "$BLUE"

        # These process every active subdomain (can be hundreds), so they need
        # real internal concurrency, not just the outer parallel-tools job
        # pool - and a much longer timeout than quick API-based sources get.
        local CRAWL_TOOLS=()
        command -v waymore &>/dev/null && CRAWL_TOOLS+=("waymore:waymore -i $domain -mode U -oU /dev/stdout")
        command -v waybackurls &>/dev/null && CRAWL_TOOLS+=("waybackurls:cat $ACTIVE_SUBDOMAINS | xargs -P $PARALLEL_JOBS -I{} sh -c 'echo {} | waybackurls' 2>/dev/null")
        command -v gau &>/dev/null && CRAWL_TOOLS+=("gau-crawl:cat $ACTIVE_SUBDOMAINS | gau --threads $PARALLEL_JOBS")
        command -v katana &>/dev/null && CRAWL_TOOLS+=("katana:katana -d 3 -jc -aff -fx -list $ACTIVE_SUBDOMAINS -c $PARALLEL_JOBS -silent")

        if [ ${#CRAWL_TOOLS[@]} -gt 0 ]; then
            run_tools_parallel CRAWL_TOOLS "$domain_output_dir/crawling" "$CRAWL_TIMEOUT_SECONDS"
        fi

        local crawl_final="$domain_output_dir/crawling/final_crawling_results.txt"
        merge_results "$domain_output_dir/crawling" "$crawl_final"

        if [ -s "$crawl_final" ]; then
            log_message "[OK] Found $(count_unique_results "$crawl_final") unique URLs from crawling" "$GREEN"

            diff_against_previous "$PREV_DIR/crawling/final_crawling_results.txt" "$crawl_final" "$domain_output_dir/crawling/new_urls.txt" "URLs"

            grep -E '\.js(\?|$)' "$crawl_final" > "$domain_output_dir/crawling/javascript_files.txt" 2>/dev/null
            grep -E '(/api/|/v[0-9]+/|\.json|/graphql)' "$crawl_final" > "$domain_output_dir/crawling/api_endpoints.txt" 2>/dev/null

            local urls_for_tagging="$crawl_final"
            if command -v uro &>/dev/null; then
                log_message "[+] Filtering URLs with uro..." "$BLUE"
                uro < "$crawl_final" > "$domain_output_dir/crawling/filtered_urls.txt"
                log_message "[OK] Filtered to $(count_unique_results "$domain_output_dir/crawling/filtered_urls.txt") unique URLs" "$GREEN"
                urls_for_tagging="$domain_output_dir/crawling/filtered_urls.txt"
            fi

            # Categorize parameterized URLs by likely vuln class - classification
            # only, no payloads are sent.
            if command -v paramx &>/dev/null && [ -s "$urls_for_tagging" ]; then
                log_message "[+] Tagging parameterized URLs with paramx..." "$BLUE"
                mkdir -p "$domain_output_dir/crawling/paramx"
                for tag in xss sqli lfi rce idor ssrf ssti redirect; do
                    paramx -tag "$tag" < "$urls_for_tagging" > "$domain_output_dir/crawling/paramx/${tag}.txt" 2>>"$CURRENT_LOG"
                    [ -s "$domain_output_dir/crawling/paramx/${tag}.txt" ] || rm -f "$domain_output_dir/crawling/paramx/${tag}.txt"
                done
            fi
        else
            log_message "[!] No crawling results found" "$YELLOW"
        fi
    fi

    # ---- Phase 7: reports ----
    local TOOL_ERRORS=()
    [ -s "$CURRENT_ERRORS" ] && mapfile -t TOOL_ERRORS < "$CURRENT_ERRORS"

    local REPORT="$domain_output_dir/report.txt"
    local total_subs active_subs crawl_count js_files api_endpoints
    total_subs=$(count_unique_results "$final_output")
    active_subs=$(count_unique_results "$ACTIVE_SUBDOMAINS")
    crawl_count=$(count_unique_results "$domain_output_dir/crawling/final_crawling_results.txt")
    js_files=$(count_unique_results "$domain_output_dir/crawling/javascript_files.txt")
    api_endpoints=$(count_unique_results "$domain_output_dir/crawling/api_endpoints.txt")

    {
        echo "=== RecoGun Scan Report ==="
        echo "Domain: $domain"
        echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"
        [[ -n "$PREV_DIR" ]] && echo "Compared against: $PREV_DIR"
        echo ""
        echo "=== Results ==="
        echo "Total Subdomains: $total_subs"
        echo "Active Subdomains: $active_subs"
        [[ -f "$domain_output_dir/new_subdomains.txt" ]] && echo "New Subdomains Since Last Scan: $(count_unique_results "$domain_output_dir/new_subdomains.txt")"
        [[ -f "$domain_output_dir/new_active_subdomains.txt" ]] && echo "New Active Subdomains Since Last Scan: $(count_unique_results "$domain_output_dir/new_active_subdomains.txt")"
        echo "URLs Found: $crawl_count"
        [[ -f "$domain_output_dir/crawling/new_urls.txt" ]] && echo "New URLs Since Last Scan: $(count_unique_results "$domain_output_dir/crawling/new_urls.txt")"
        echo "JavaScript Files: $js_files"
        echo "API Endpoints: $api_endpoints"
        if $PORT_DISCOVERY; then
            echo "Open Ports (passive): $(count_unique_results "$domain_output_dir/naabu.txt")"
        fi
        if $ORIGIN_IP_DISCOVERY; then
            echo "Origin IP Candidates: $(count_unique_results "$domain_output_dir/origin_ip/candidate_ips.txt")"
            echo "Verified Origin IPs: $(count_unique_results "$domain_output_dir/origin_ip/verified_origin_ips.txt")"
        fi
        echo ""

        local has_takeovers=false has_origin=false
        [ -s "$domain_output_dir/takeovers.txt" ] && has_takeovers=true
        $ORIGIN_IP_DISCOVERY && [ -s "$domain_output_dir/origin_ip/verified_origin_ips.txt" ] && has_origin=true
        if $has_takeovers || $has_origin; then
            echo "=== Security Findings ==="
            $has_takeovers && echo "Potential Subdomain Takeovers Found - see takeovers.txt"
            $has_origin && echo "Verified Origin IP(s) found - WAF/CDN can likely be bypassed, see origin_ip/verified_origin_ips.txt"
            echo ""
        fi

        if [ -d "$domain_output_dir/crawling/paramx" ] && [ "$(ls -A "$domain_output_dir/crawling/paramx" 2>/dev/null)" ]; then
            echo "=== Parameter Triage (paramx) ==="
            for f in "$domain_output_dir/crawling/paramx"/*.txt; do
                echo "$(basename "$f" .txt): $(count_unique_results "$f") URLs"
            done
            echo ""
        fi

        if [ ${#TOOL_ERRORS[@]} -gt 0 ]; then
            echo "=== Tool Errors ==="
            printf '%s\n' "${TOOL_ERRORS[@]}"
            echo ""
        fi

        echo "=== File Locations ==="
        echo "All Subdomains: $final_output"
        echo "Active Subdomains: $ACTIVE_SUBDOMAINS"
        echo "Crawling Results: $domain_output_dir/crawling/"
        echo "Log File: $CURRENT_LOG"
        echo "JSON Report: $domain_output_dir/report.json"
    } > "$REPORT"

    log_message "[+] Report saved to $REPORT" "$GREEN"
    export_json "$domain" "$domain_output_dir" "$final_output"

    echo ""
    log_message "=== SCAN SUMMARY ===" "$CYAN"
    log_message "Domain: $domain" "$CYAN"
    log_message "Total Subdomains: $total_subs" "$CYAN"
    log_message "Active Subdomains: $active_subs" "$CYAN"
    if [ ${#TOOL_ERRORS[@]} -gt 0 ]; then
        log_message "Failed Tools: ${#TOOL_ERRORS[@]}" "$RED"
    fi
    echo ""
}

# Report which external tools/keys are available, grouped by phase. Purely
# informational - RecoGun already skips missing tools gracefully at scan
# time, this just gives visibility before you commit to a run.
check_dependencies() {
    echo -e "${PURPLE}=== RecoGun Dependency Check ===${RESET}"

    local total=0
    local found=0
    local current_category=""

    _dep_check() {
        local category="$1"
        local tool="$2"
        local envvar="$3"

        if [[ "$category" != "$current_category" ]]; then
            echo ""
            echo -e "${CYAN}${category}${RESET}"
            current_category="$category"
        fi

        total=$((total + 1))
        local env_str=""
        if [[ -n "$envvar" ]]; then
            if [[ -n "${!envvar}" ]]; then
                env_str=" (${envvar}: configured)"
            else
                env_str=" (${envvar}: not set)"
            fi
        fi

        if command -v "$tool" &>/dev/null; then
            found=$((found + 1))
            echo -e "  ${GREEN}[OK]${RESET}      ${tool}${env_str}"
        else
            echo -e "  ${RED}[MISSING]${RESET} ${tool}${env_str}"
        fi
    }

    _dep_check "Core (required for any scan)" curl ""
    _dep_check "Core (required for any scan)" jq ""
    _dep_check "Core (required for any scan)" httpx ""

    _dep_check "Passive subdomain enumeration" subfinder ""
    _dep_check "Passive subdomain enumeration" assetfinder ""
    _dep_check "Passive subdomain enumeration" findomain ""
    _dep_check "Passive subdomain enumeration" amass ""
    _dep_check "Passive subdomain enumeration" cero ""
    _dep_check "Passive subdomain enumeration" sublist3r ""
    _dep_check "Passive subdomain enumeration" gau ""
    _dep_check "Passive subdomain enumeration" haktrails ""
    _dep_check "Passive subdomain enumeration" chaos CHAOS_API_KEY
    _dep_check "Passive subdomain enumeration" shosubgo SHODAN_API_KEY
    _dep_check "Passive subdomain enumeration" censys CENSYS_API_KEY
    _dep_check "Passive subdomain enumeration" github-subdomains GITHUB_TOKEN
    _dep_check "Passive subdomain enumeration" gitlab-subdomains GITLAB_TOKEN

    _dep_check "Permutation + bruteforce (-b)" dig ""
    _dep_check "Permutation + bruteforce (-b)" dnsgen ""
    _dep_check "Permutation + bruteforce (-b)" alterx ""
    _dep_check "Permutation + bruteforce (-b)" shuffledns ""
    _dep_check "Permutation + bruteforce (-b)" puredns ""
    _dep_check "Permutation + bruteforce (-b)" dnsrecon ""

    _dep_check "Passive port discovery (-p)" naabu ""

    _dep_check "Origin IP discovery (-o)" wafw00f ""
    _dep_check "Origin IP discovery (-o)" shodan SHODAN_API_KEY
    _dep_check "Origin IP discovery (-o)" uncover ""

    _dep_check "Subdomain takeover" subzy ""

    _dep_check "Crawling" waymore ""
    _dep_check "Crawling" waybackurls ""
    _dep_check "Crawling" katana ""
    _dep_check "Crawling" uro ""
    _dep_check "Crawling" paramx ""

    echo ""
    echo -e "${CYAN}Origin IP discovery (-o) - favicon hashing${RESET}"
    total=$((total + 1))
    if command -v python3 &>/dev/null && python3 -c "import mmh3" &>/dev/null 2>&1; then
        found=$((found + 1))
        echo -e "  ${GREEN}[OK]${RESET}      python3 + mmh3 module"
    else
        echo -e "  ${RED}[MISSING]${RESET} python3 + mmh3 module (pip install mmh3)"
    fi

    unset -f _dep_check

    echo ""
    echo -e "${PURPLE}----------------------------------------------${RESET}"
    echo "  $found/$total tools found"
    echo -e "${PURPLE}----------------------------------------------${RESET}"
    echo ""
    echo "Notes:"
    echo "  - Missing tools are not a hard failure - RecoGun skips them"
    echo "    automatically at scan time and logs why. This is visibility,"
    echo "    not a gate."
    echo "  - The 'shodan' CLI needs its own one-time auth even if"
    echo "    SHODAN_API_KEY is set in config.env: run 'shodan init <key>'."
    echo "  - 'uncover' reads its own provider config (~/.config/pdcp/), not"
    echo "    config.env - configure it separately if you use -o."
}

show_usage() {
    echo -e "${BLUE}RecoGun - Automated Subdomain Enumeration and Reconnaissance${RESET}"
    echo ""
    echo -e "${GREEN}Usage:${RESET}"
    echo "  $0 -d <domain>              # Scan single domain"
    echo "  $0 -l <domains_file>        # Scan multiple domains from file"
    echo "  $0 -d <domain> -t <tools>   # Run specific tools only (comma separated)"
    echo "  $0 -d <domain> -e <tools>   # Exclude specific tools (comma separated)"
    echo "  $0 -d <domain> -x <oos.txt> # Exclude out-of-scope subdomains/patterns"
    echo "  $0 -d <domain> -i <in.txt>  # Restrict to an include-only subdomain scope"
    echo "  $0 -d <domain> -b           # Include DNS permutation + wordlist bruteforce"
    echo "  $0 -d <domain> -p           # Include passive port discovery (naabu -passive)"
    echo "  $0 -d <domain> -o           # Include origin IP discovery (behind WAF/CDN)"
    echo "  $0 -d <domain> -j <n>       # Max parallel tool jobs (default: 8)"
    echo "  $0 -d <domain> -v           # Verbose - log the actual command run per tool (keys redacted)"
    echo "  $0 -c                       # Check which dependencies/API keys are available, then exit"
    echo ""
    echo -e "${GREEN}Notes:${RESET}"
    echo "  - Every run prints a config summary (target, active flags, scope,"
    echo "    parallel jobs) before scanning starts, so you can see exactly what"
    echo "    is about to run."
    echo "  - If a previous scan exists for the domain in results/, new subdomains,"
    echo "    active hosts, and URLs are automatically diffed and reported."
    echo "  - Scope files (-x/-i) accept exact subdomains or *.domain.tld wildcards,"
    echo "    one per line, # for comments."
    echo "  - Origin IP discovery (-o) gathers candidates from VirusTotal, AlienVault,"
    echo "    URLScan, Shodan cert search, uncover and favicon hashing, then confirms"
    echo "    them with a direct GET (Host header spoofed) - no exploitation, just"
    echo "    fingerprinting. Runs once per domain, not per subdomain."
    echo ""
    echo -e "${GREEN}Examples:${RESET}"
    echo "  $0 -d example.com"
    echo "  $0 -d example.com -t subfinder,assetfinder,crtsh"
    echo "  $0 -d example.com -e amass,chaos -b -p"
    echo "  $0 -d example.com -x oos.txt -i in.txt"
    echo "  $0 -d example.com -o"
    echo "  $0 -l domains.txt -j 16"
}

while getopts "d:l:x:i:t:e:j:bpocvh" opt; do
    case "$opt" in
        d) DOMAIN="$OPTARG" ;;
        l) DOMAINS_FILE="$OPTARG" ;;
        x) OOS_FILE="$OPTARG" ;;
        i) INCLUDE_FILE="$OPTARG" ;;
        t) IFS=',' read -ra TOOLS_TO_RUN <<< "$(echo "$OPTARG" | tr -d ' ')" ;;
        e) IFS=',' read -ra TOOLS_TO_EXCLUDE <<< "$(echo "$OPTARG" | tr -d ' ')" ;;
        j) PARALLEL_JOBS="$OPTARG" ;;
        b) BRUTEFORCE=true ;;
        p) PORT_DISCOVERY=true ;;
        o) ORIGIN_IP_DISCOVERY=true ;;
        v) VERBOSE=true ;;
        c) check_dependencies; exit 0 ;;
        h) show_usage; exit 0 ;;
        *) show_usage; exit 1 ;;
    esac
done

if [[ -z "$DOMAIN" && -z "$DOMAINS_FILE" ]]; then
    echo -e "${RED}Error: You must specify either a domain (-d) or a domains file (-l)${RESET}"
    show_usage
    exit 1
fi

if [[ -n "$DOMAINS_FILE" && ! -f "$DOMAINS_FILE" ]]; then
    echo -e "${RED}Error: Domains file '$DOMAINS_FILE' not found${RESET}"
    exit 1
fi

if [[ -n "$OOS_FILE" && ! -f "$OOS_FILE" ]]; then
    echo -e "${RED}Error: Out-of-scope file '$OOS_FILE' not found${RESET}"
    exit 1
fi

if [[ -n "$INCLUDE_FILE" && ! -f "$INCLUDE_FILE" ]]; then
    echo -e "${RED}Error: Include-scope file '$INCLUDE_FILE' not found${RESET}"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo -e "${PURPLE}"
echo "  +=========================================+"
echo "  |              RecoGun v4.4                |"
echo "  |    Automated Reconnaissance Tool         |"
echo "  +=========================================+"
echo -e "${RESET}"

# Show exactly what this run will actually do before it starts - which
# optional phases are on, what scope/tuning is in effect. -v additionally
# logs the real (secret-redacted) command line for every tool as it runs.
echo -e "${CYAN}Target:${RESET}            ${DOMAIN:-$DOMAINS_FILE}"
echo -e "${CYAN}Bruteforce (-b):${RESET}   $BRUTEFORCE"
echo -e "${CYAN}Port scan (-p):${RESET}    $PORT_DISCOVERY"
echo -e "${CYAN}Origin IP (-o):${RESET}    $ORIGIN_IP_DISCOVERY"
echo -e "${CYAN}Include scope:${RESET}     ${INCLUDE_FILE:-none}"
echo -e "${CYAN}Exclude scope:${RESET}     ${OOS_FILE:-none}"
[ ${#TOOLS_TO_RUN[@]} -gt 0 ] && echo -e "${CYAN}Only tools:${RESET}        ${TOOLS_TO_RUN[*]}"
[ ${#TOOLS_TO_EXCLUDE[@]} -gt 0 ] && echo -e "${CYAN}Excluded tools:${RESET}    ${TOOLS_TO_EXCLUDE[*]}"
echo -e "${CYAN}Parallel jobs:${RESET}     $PARALLEL_JOBS"
echo -e "${CYAN}Verbose (-v):${RESET}      $VERBOSE"
echo ""

if [[ -n "$DOMAIN" ]]; then
    process_domain "$DOMAIN"
elif [[ -n "$DOMAINS_FILE" ]]; then
    log_message "[*] Processing domains from file: $DOMAINS_FILE" "$BLUE"
    while IFS= read -r domain || [[ -n "$domain" ]]; do
        [[ -z "$domain" || "$domain" =~ ^[[:space:]]*# ]] && continue
        process_domain "$(echo "$domain" | xargs)"
        echo ""
    done < "$DOMAINS_FILE"
fi

log_message "[OK] RecoGun scan completed!" "$GREEN"
