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

OPERATOR="${OPERATOR:-m0442}"

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
CRAWLING=false
PARAM_DISCOVERY=false
VERBOSE=false
PERMUTATION_WORDLIST_CUSTOM=false
ONLY_PHASES=()          # if non-empty, run ONLY these phases
INPUT_HOSTS_FILE=""     # -f: pre-existing host list for downstream-only phases
OUTPUT_COLLECT_DIR=""   # -O: collect each domain's key output as <root>.txt here
RESOLVERS_FILE="${RESOLVERS_FILE:-$SCRIPT_DIR/resolvers.txt}"
WORDLISTS_DIR="${WORDLISTS_DIR:-$SCRIPT_DIR/wordlists}"
WORDLIST_FILE="${WORDLIST_FILE:-$WORDLISTS_DIR/subdomains.txt}"
PERMUTATION_WORDLIST="${PERMUTATION_WORDLIST:-$WORDLISTS_DIR/permutations.txt}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-300}"
CRAWL_TIMEOUT_SECONDS="${CRAWL_TIMEOUT_SECONDS:-1800}"
PARALLEL_JOBS="${PARALLEL_JOBS:-8}"
HTTPX_THREADS="${HTTPX_THREADS:-100}"
ACTIVE_SUBDOMAINS=""
CURRENT_LOG=""
CURRENT_ERRORS=""
PREV_DIR=""
LAST_DOMAIN_OUTPUT_DIR=""

# OTX auth header, expanded into tool commands. No space after the colon so
# it survives unquoted word-splitting through `bash -c` as exactly two args
# (-H  X-OTX-API-KEY:<key>); empty when no key, which curl simply ignores.
OTX_HDR=""
[[ -n "$OTX_API_KEY" ]] && OTX_HDR="-H X-OTX-API-KEY:$OTX_API_KEY"

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

# Registered root domain for a host (public-suffix-aware via tldextract so
# a.b.example.co.uk -> example.co.uk, not co.uk). Falls back to a naive
# last-two-labels split if tldextract isn't available.
_TLDEXTRACT_OK=""
root_domain() {
    local host="$1"
    host="${host#*://}"       # strip scheme if a URL slipped in
    host="${host%%/*}"        # strip path
    host="${host%%:*}"        # strip port
    if [ -z "$_TLDEXTRACT_OK" ]; then
        if command -v python3 &>/dev/null && python3 -c "import tldextract" &>/dev/null 2>&1; then
            _TLDEXTRACT_OK=yes
        else
            _TLDEXTRACT_OK=no
        fi
    fi
    if [ "$_TLDEXTRACT_OK" = yes ]; then
        python3 -c "import sys,tldextract; print(tldextract.extract(sys.argv[1]).registered_domain)" "$host" 2>/dev/null
    else
        echo "$host" | awk -F. '{ if (NF>=2) print $(NF-1)"."$NF; else print $0 }'
    fi
}

# --only gate: is this phase in the explicit --only list? With no --only
# list, every phase passes this gate and normal flag-driven behavior applies.
# Phase names: enum, bruteforce, probe, origin, ports, takeover, crawl.
phase_enabled() {
    local phase="$1"
    if [ ${#ONLY_PHASES[@]} -eq 0 ]; then
        return 0
    fi
    [[ " ${ONLY_PHASES[*]} " == *" $phase "* ]]
}

# Opt-in phases (origin/ports/crawl/bruteforce) normally require their own
# flag (-o/-p/-C/-b). But naming one in --only is itself the opt-in, so this
# runs the phase if EITHER its flag is set OR --only names it. Always subject
# to the --only gate above, so --only never runs anything it didn't name.
optin_phase_runs() {
    local phase="$1"
    local flag_set="$2"   # "true"/"false" - the phase's own -flag
    phase_enabled "$phase" || return 1
    if [ ${#ONLY_PHASES[@]} -gt 0 ]; then
        return 0          # named in --only => run it
    fi
    [[ "$flag_set" == "true" ]]
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
# Optional 5th/6th args (used by run_tools_parallel) drive a live "[done/total]"
# progress tag: a counter file to atomically increment, and the total tool count.
run_tool() {
    local tool_name="$1"
    local command="$2"
    local output_file="$3"
    local tool_timeout="${4:-$TIMEOUT_SECONDS}"
    local counter_file="${5:-}"
    local total="${6:-}"

    local start_ts end_ts elapsed
    start_ts=$(date +%s)

    log_message "[+] Running $tool_name..." "$BLUE"
    $VERBOSE && log_message "    -> $(redact_command "$command")" "$CYAN"

    local rc=0
    timeout "$tool_timeout" bash -c "$command" > "$output_file" 2>> "$CURRENT_LOG" || rc=$?

    end_ts=$(date +%s)
    elapsed=$(( end_ts - start_ts ))

    # Live progress: record this completion and render [done/total]. Each tool
    # runs in its own background subshell, so we can't share a shell variable -
    # instead every finisher appends one line and the done-count is the line
    # count. A single `>>` write of a short line is atomic on POSIX, so no lock
    # is needed (and no dependency on flock, which isn't everywhere).
    local prog=""
    if [ -n "$counter_file" ] && [ -n "$total" ]; then
        echo "$tool_name" >> "$counter_file"
        local done
        done=$(wc -l < "$counter_file" 2>/dev/null | tr -d ' ')
        prog="[${done}/${total}] "
    fi

    if [ "$rc" -eq 0 ]; then
        if [ -s "$output_file" ]; then
            local count
            count=$(count_unique_results "$output_file")
            log_message "${prog}[OK] $tool_name done in ${elapsed}s - $count results" "$GREEN"
        else
            log_message "${prog}[!] $tool_name done in ${elapsed}s - no results" "$YELLOW"
        fi
    else
        # 124 is timeout(1)'s exit code for the timeout expiring.
        if [ "$rc" -eq 124 ]; then
            log_message "${prog}[X] $tool_name TIMED OUT after ${tool_timeout}s - skipping" "$RED"
        else
            log_message "${prog}[X] $tool_name failed (exit $rc) after ${elapsed}s - skipping" "$RED"
        fi
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

    local total="${#tools_ref[@]}"
    [ "$total" -eq 0 ] && return 0

    # Shared [done/total] counter for the live progress tags: each finishing
    # tool appends one line, done-count = line count. Start empty (0 lines).
    local counter_file="$output_dir/.progress"
    : > "$counter_file"

    # Announce the line-up up front so you know what's about to run in parallel.
    local names=()
    for tool in "${tools_ref[@]}"; do names+=("${tool%%:*}"); done
    log_message "[*] Launching $total tool(s) in parallel (max $PARALLEL_JOBS at once): ${names[*]}" "$CYAN"

    for tool in "${tools_ref[@]}"; do
        local tool_name="${tool%%:*}"
        local tool_command="${tool#*:}"
        run_tool "$tool_name" "$tool_command" "$output_dir/${tool_name}.txt" "$job_timeout" "$counter_file" "$total" &
        while [ "$(jobs -r -p | wc -l)" -ge "$PARALLEL_JOBS" ]; do
            wait -n
        done
    done
    wait

    rm -f "$counter_file" "$counter_file.lock"
    log_message "[*] All $total tool(s) finished" "$CYAN"
}

merge_results() {
    local dir="$1"
    local dest="$2"
    cat "$dir"/*.txt 2>/dev/null | sed '/^\s*$/d' | sort -u > "$dest"
}

# Download every JS URL in a list into a folder, in parallel (capped). Each
# file is named by a hash of its URL (so two different URLs never collide and
# re-runs are stable), with a .url sidecar recording the source URL. Skips
# non-JS/empty responses. Feeds the jsanalysis phase.
download_js_files() {
    local url_list="$1"
    local dest_dir="$2"
    [ -s "$url_list" ] || { log_message "[i] No JS URLs to download" "$YELLOW"; return; }
    mkdir -p "$dest_dir"

    log_message "[+] Downloading $(count_unique_results "$url_list") JS files into $(basename "$dest_dir")/ ..." "$BLUE"
    local hasher="md5sum"
    command -v md5sum &>/dev/null || hasher="shasum"

    # Process-substitution (not a pipe) so this loop runs in the CURRENT shell -
    # a piped `... | while` runs in a subshell, so the parent `wait` below would
    # wait for nothing and the count would race ahead of the downloads.
    while IFS= read -r url || [[ -n "$url" ]]; do
        [[ -z "$url" ]] && continue
        (
            local h base out
            h=$(printf '%s' "$url" | $hasher | awk '{print $1}')
            base=$(printf '%s' "$url" | sed 's#.*/##; s/[?#].*//; s/[^A-Za-z0-9._-]/_/g')
            [ -z "$base" ] && base="script"
            out="$dest_dir/${base}.${h:0:10}.js"
            if curl -sk --max-time 20 -A "Mozilla/5.0" "$url" -o "$out" 2>/dev/null; then
                # Drop empties and obvious HTML error pages - keep real JS only.
                if [ ! -s "$out" ] || head -c 200 "$out" | grep -qiE '<!doctype html|<html'; then
                    rm -f "$out"
                else
                    printf '%s\n' "$url" > "$out.url"
                fi
            fi
        ) &
        while [ "$(jobs -r -p | wc -l)" -ge "$PARALLEL_JOBS" ]; do wait -n; done
    done < <(sort -u "$url_list")
    wait

    local n
    n=$(find "$dest_dir" -maxdepth 1 -name '*.js' 2>/dev/null | wc -l)
    log_message "[OK] Downloaded $n JS files" "$GREEN"
}

# Full JavaScript intelligence extraction over a folder of downloaded .js
# files. Everything here is offline pattern-matching against already-fetched
# content - no requests to the target. Each category writes its own file so
# you can grep/triage per class; a findings summary tallies hit counts.
#
# Categories map to the attack-surface list a bug-bounty JS review looks for:
# secrets, cloud resources, endpoints/APIs, auth, DOM sinks/sources, storage,
# third-party services, library fingerprints, source maps, and more.
analyze_js() {
    local js_dir="$1"
    local out_dir="$2"

    local files
    files=$(find "$js_dir" -maxdepth 1 -name '*.js' 2>/dev/null)
    if [ -z "$files" ]; then
        log_message "[!] No downloaded JS files to analyze in $js_dir" "$YELLOW"
        return 1
    fi
    mkdir -p "$out_dir"
    local count
    count=$(printf '%s\n' "$files" | grep -c . )
    log_message "[*] Analyzing $count JS files for attack surface..." "$BLUE"

    # category|extended-regex . grep -hoiE across all files, sort -u per file.
    # Ordering roughly by triage priority (secrets/cloud first).
    local -a PATTERNS=(
      # --- Secrets / credentials / keys ---
      "secrets_aws_akid|AKIA[0-9A-Z]{16}"
      "secrets_aws_secret|aws_secret_access_key['\"]?[[:space:]]*[:=][[:space:]]*['\"][A-Za-z0-9/+=]{40}['\"]"
      "secrets_google_api|AIza[0-9A-Za-z_-]{35}"
      "secrets_gcp_oauth|[0-9]+-[0-9a-z_]{32}\.apps\.googleusercontent\.com"
      "secrets_firebase|AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}"
      "secrets_slack|xox[baprs]-[0-9A-Za-z-]{10,72}"
      "secrets_slack_webhook|https://hooks\.slack\.com/services/[A-Za-z0-9/]+"
      "secrets_github_pat|gh[pousr]_[A-Za-z0-9]{36,}"
      "secrets_gitlab_pat|glpat-[A-Za-z0-9_-]{20}"
      "secrets_stripe|(sk|pk|rk)_(live|test)_[0-9A-Za-z]{24,}"
      "secrets_square|sq0(atp|csp)-[0-9A-Za-z_-]{22,}"
      "secrets_paypal_braintree|access_token\\\$production\\\$[0-9a-z]{16}\\\$[0-9a-f]{32}"
      "secrets_twilio|SK[0-9a-fA-F]{32}"
      "secrets_sendgrid|SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"
      "secrets_mailgun|key-[0-9a-zA-Z]{32}"
      "secrets_mailchimp|[0-9a-f]{32}-us[0-9]{1,2}"
      "secrets_npm|npm_[A-Za-z0-9]{36}"
      "secrets_openai|sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}"
      "secrets_anthropic|sk-ant-[A-Za-z0-9_-]{20,}"
      "secrets_jwt|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
      "secrets_private_key|-----BEGIN (RSA|EC|DSA|OPENSSH|PGP)? ?PRIVATE KEY-----"
      "secrets_bearer|[Bb]earer[[:space:]]+[A-Za-z0-9._-]{20,}"
      "secrets_generic_apikey|(api[_-]?key|apikey|client[_-]?secret|secret[_-]?key|access[_-]?token)['\"]?[[:space:]]*[:=][[:space:]]*['\"][A-Za-z0-9._-]{16,}['\"]"
      "secrets_password_assign|(password|passwd|pwd)['\"]?[[:space:]]*[:=][[:space:]]*['\"][^'\"[:space:]]{4,}['\"]"

      # --- Cloud resources ---
      "cloud_s3|[A-Za-z0-9._-]+\.s3(\.[a-z0-9-]+)?\.amazonaws\.com|s3://[A-Za-z0-9._-]+"
      "cloud_cloudfront|[A-Za-z0-9]+\.cloudfront\.net"
      "cloud_azure_blob|[A-Za-z0-9]+\.blob\.core\.windows\.net"
      "cloud_azure_other|[A-Za-z0-9-]+\.(azurewebsites|azure-api|azureedge|table\.core\.windows|queue\.core\.windows)\.net"
      "cloud_gcs|storage\.googleapis\.com/[A-Za-z0-9._-]+|[A-Za-z0-9._-]+\.storage\.googleapis\.com"
      "cloud_gcp_functions|[a-z0-9-]+\.cloudfunctions\.net"
      "cloud_firebase_db|[A-Za-z0-9-]+\.firebaseio\.com|[A-Za-z0-9-]+\.firebaseapp\.com"
      "cloud_digitalocean_spaces|[A-Za-z0-9.-]+\.digitaloceanspaces\.com"

      # --- Endpoints / APIs / routes ---
      "endpoints_paths|['\"](/[A-Za-z0-9._/-]{2,})['\"]"
      "endpoints_api|['\"](/(api|rest|v[0-9]+|internal|admin|private|gateway)/[A-Za-z0-9._/-]*)['\"]"
      "endpoints_graphql|(/graphql[a-z0-9/_-]*|graphql['\"]?[[:space:]]*[:=]|__schema|gql\`)"
      "endpoints_websocket|wss?://[A-Za-z0-9._:/?=&-]+"
      "endpoints_absolute_urls|https?://[A-Za-z0-9._-]+(:[0-9]+)?(/[A-Za-z0-9._/?#=&%-]*)?"
      "endpoints_upload|['\"](/[A-Za-z0-9._/-]*(upload|import|attachment|file)[A-Za-z0-9._/-]*)['\"]"
      "endpoints_download|['\"](/[A-Za-z0-9._/-]*(download|export|report|invoice)[A-Za-z0-9._/-]*)['\"]"
      "endpoints_admin_debug|['\"](/[A-Za-z0-9._/-]*(admin|debug|internal|test|staging|dev|actuator|swagger|graphiql|metrics|healthz?)[A-Za-z0-9._/-]*)['\"]"

      # --- Internal / infra references ---
      "infra_internal_hosts|(localhost|127\.0\.0\.1|0\.0\.0\.0|[A-Za-z0-9-]+\.(internal|local|corp|intranet|test|staging|dev|qa)\.[A-Za-z0-9.-]+)"
      "infra_ip_addresses|([0-9]{1,3}\.){3}[0-9]{1,3}"
      "infra_staging_refs|(staging|preprod|pre-prod|uat|sandbox|dev-|test-|qa-)[A-Za-z0-9.-]*"

      # --- Auth / identity ---
      "auth_oauth|(oauth2?|/authorize|/oauth/token|response_type=|grant_type=|client_id=|redirect_uri=|code_challenge|code_verifier|pkce)"
      "auth_openid|(\.well-known/openid-configuration|id_token|nonce=|/userinfo)"
      "auth_saml|(SAMLRequest|SAMLResponse|/saml/|samlp:)"
      "auth_providers|(auth0\.com|okta\.com|onelogin\.com|pingidentity|cognito-idp\.[a-z0-9-]+\.amazonaws\.com|login\.microsoftonline\.com|accounts\.google\.com)"

      # --- Client-side vuln indicators (sinks/sources) ---
      "sink_dom_xss|(\.innerHTML|\.outerHTML|document\.write|insertAdjacentHTML|\.setHTML|dangerouslySetInnerHTML)"
      "sink_eval|(\beval\(|new Function\(|setTimeout\([^,]*['\"]|setInterval\([^,]*['\"])"
      "sink_postmessage|(addEventListener\(['\"]message['\"]|onmessage[[:space:]]*=|\.postMessage\()"
      "sink_open_redirect|(location\.(href|replace|assign)[[:space:]]*=|window\.location[[:space:]]*=|\.location[[:space:]]*=[[:space:]]*[A-Za-z_])"
      "source_taint|(location\.(hash|search|href)|document\.(URL|referrer|cookie)|window\.name|URLSearchParams)"
      "sink_prototype_pollution|(__proto__|constructor\.prototype|Object\.assign\(|\.merge\(|\.extend\()"
      "sink_template_injection|(v-html|ng-bind-html|\{\{.*\}\}|\$\{[^}]+\}|Handlebars\.|_\.template)"

      # --- Storage / client state ---
      "storage_local|localStorage\.(setItem|getItem)"
      "storage_session|sessionStorage\.(setItem|getItem)"
      "storage_indexeddb|(indexedDB\.open|IDBDatabase|objectStore)"
      "storage_cookies|(document\.cookie|Cookies\.set|js-cookie)"

      # --- Crypto ---
      "crypto_usage|(crypto\.subtle|window\.crypto|CryptoJS|forge\.|sjcl\.|createCipheriv|createHash\()"

      # --- Third-party / analytics / payment ---
      "thirdparty_analytics|(google-analytics\.com|googletagmanager\.com|gtag\(|segment\.com|mixpanel|amplitude|hotjar|fullstory|sentry\.io|bugsnag|datadoghq)"
      "thirdparty_payment|(stripe\.com|js\.stripe\.com|braintreegateway|paypal\.com/sdk|checkout\.com|adyen|square(up)?\.com|razorpay)"
      "thirdparty_maps|(maps\.googleapis\.com|mapbox\.com|api\.tomtom\.com)"
      "thirdparty_cdn|(cdnjs\.cloudflare\.com|jsdelivr\.net|unpkg\.com|cdn\.jsdelivr)"

      # --- AI / LLM / vector ---
      "ai_endpoints|(api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis|api\.cohere|huggingface\.co|/v1/(chat/completions|completions|embeddings)|pinecone\.io|weaviate|qdrant|/vectors?/)"

      # --- Config / feature flags / debug ---
      "config_feature_flags|(featureFlag|feature_flag|launchdarkly|split\.io|unleash|isEnabled\(|toggles?\[)"
      "config_debug|(debug[[:space:]]*[:=][[:space:]]*true|DEBUG[[:space:]]*=[[:space:]]*true|console\.(debug|trace)|__DEV__)"
      "config_env_leak|(process\.env\.[A-Z_]+|import\.meta\.env\.[A-Z_]+|window\.__ENV__|window\.__CONFIG__)"

      # --- Security headers referenced in JS ---
      "security_csp_cors|(Content-Security-Policy|Access-Control-Allow-Origin|crossorigin|withCredentials[[:space:]]*[:=][[:space:]]*true)"

      # --- Modern app structure ---
      "structure_dynamic_import|(import\([\`'\"]|require\.ensure|__webpack_require__|loadChunk|import\(/\* webpackChunkName)"
      "structure_workers|(new Worker\(|new SharedWorker\(|navigator\.serviceWorker|registerServiceWorker|workbox)"
      "structure_wasm|(WebAssembly\.|\.wasm['\"])"

      # --- Source maps ---
      "sourcemaps|(sourceMappingURL=[A-Za-z0-9._/-]+\.map|//# sourceMappingURL)"
    )

    # Findings live in a subfolder so the category files don't clutter the
    # analysis dir root (which also holds the external-tool outputs + reports).
    local find_dir="$out_dir/findings"
    mkdir -p "$find_dir"

    local summary="$out_dir/_SUMMARY.txt"
    local findings_md="$out_dir/_FINDINGS.md"
    : > "$summary"
    : > "$findings_md"

    # High-signal categories bubble to the top of _FINDINGS.md so the stuff
    # worth looking at first (secrets, keys, tokens) isn't buried in noise.
    local HIGH_SIGNAL_RX='^(secrets_|cloud_|auth_|infra_internal)'

    {
        echo "=== RecoGun JS Analysis Summary ==="
        echo "Files analyzed: $count"
        echo "Generated: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Per-category detail: findings/<category>.txt"
        echo "Prioritized view:    _FINDINGS.md"
        echo ""
        printf "%-34s %6s\n" "CATEGORY" "HITS"
        printf "%-34s %6s\n" "--------" "----"
    } >> "$summary"

    # Two-pass: collect category->count first so _FINDINGS.md can list the
    # high-signal hits before the bulk, then render both reports.
    local -a hi_lines=() lo_lines=()

    for entry in "${PATTERNS[@]}"; do
        local cat="${entry%%|*}"
        local rx="${entry#*|}"
        local of="$find_dir/${cat}.txt"

        # Per-file so we can attribute each hit to its source JS. grep -oiE gives
        # only the matched value; we prefix the (basename of the) source file so
        # the category file is actually readable, not a context-free blob.
        : > "$of.tmp"
        local f
        for f in $files; do
            grep -hoiE "$rx" "$f" 2>/dev/null \
                | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' \
                | sort -u \
                | sed "s#^#$(basename "$f")\t#"
        done > "$of.tmp"

        local hits
        hits=$(wc -l < "$of.tmp" | tr -d ' ')
        if [ "$hits" -gt 0 ]; then
            # Readable category file: header + aligned "value  <-  source.js" rows,
            # values grouped so the same finding across many files collapses.
            {
                echo "# $cat"
                echo "# $hits occurrence(s) across the analyzed JS. Format: VALUE <TAB> source file"
                echo "# ---------------------------------------------------------------"
                # value-first, then its source(s), sorted by value
                awk -F'\t' '{ v[$2]=v[$2] (v[$2]?", ":"") $1 } END { for (k in v) print k "\t<-  " v[k] }' "$of.tmp" \
                    | sort
            } > "$of"
            rm -f "$of.tmp"

            local uniq_vals
            uniq_vals=$(grep -vc '^#' "$of")
            printf "%-34s %6s\n" "$cat" "$uniq_vals" >> "$summary"

            if [[ "$cat" =~ $HIGH_SIGNAL_RX ]]; then
                hi_lines+=("$cat|$uniq_vals")
            else
                lo_lines+=("$cat|$uniq_vals")
            fi
        else
            rm -f "$of.tmp"
        fi
    done

    # --- Human-first prioritized report ---
    {
        echo "# JS Analysis — Prioritized Findings"
        echo ""
        echo "**Files analyzed:** $count  |  **Generated:** $(date '+%Y-%m-%d %H:%M:%S')"
        echo ""
        echo "Full per-category detail is in \`findings/<category>.txt\`."
        echo ""
        if [ ${#hi_lines[@]} -gt 0 ]; then
            echo "## 🔴 High signal — review first"
            echo ""
            echo "| Category | Unique hits | File |"
            echo "|---|---:|---|"
            local l
            for l in "${hi_lines[@]}"; do
                printf "| %s | %s | \`findings/%s.txt\` |\n" "${l%%|*}" "${l#*|}" "${l%%|*}"
            done
            echo ""
        fi
        if [ ${#lo_lines[@]} -gt 0 ]; then
            echo "## Everything else"
            echo ""
            echo "| Category | Unique hits | File |"
            echo "|---|---:|---|"
            local l
            for l in "${lo_lines[@]}"; do
                printf "| %s | %s | \`findings/%s.txt\` |\n" "${l%%|*}" "${l#*|}" "${l%%|*}"
            done
            echo ""
        fi
        if [ ${#hi_lines[@]} -eq 0 ] && [ ${#lo_lines[@]} -eq 0 ]; then
            echo "_No findings matched any category._"
        fi
    } >> "$findings_md"

    # --- External specialist tools, used when installed (graceful skip) ---
    # These complement the built-in regex pass with maintained rule sets.
    if command -v trufflehog &>/dev/null; then
        log_message "[+] Running trufflehog (verified secrets)..." "$BLUE"
        trufflehog filesystem "$js_dir" --no-update --json > "$out_dir/_trufflehog.json" 2>>"$CURRENT_LOG" || true
        [ -s "$out_dir/_trufflehog.json" ] && printf "%-32s %s\n" "trufflehog_findings" "$(wc -l < "$out_dir/_trufflehog.json")" >> "$summary"
    fi
    # SecretFinder / LinkFinder / endext operate per-file on JS.
    local jf
    if command -v secretfinder &>/dev/null || command -v SecretFinder.py &>/dev/null; then
        local sf; sf=$(command -v secretfinder || command -v SecretFinder.py)
        log_message "[+] Running SecretFinder..." "$BLUE"
        for jf in $files; do "$sf" -i "$jf" -o cli >> "$out_dir/_secretfinder.txt" 2>>"$CURRENT_LOG" || true; done
        [ -s "$out_dir/_secretfinder.txt" ] && printf "%-32s %s\n" "secretfinder_lines" "$(wc -l < "$out_dir/_secretfinder.txt")" >> "$summary"
    fi
    if command -v linkfinder &>/dev/null || command -v LinkFinder.py &>/dev/null; then
        local lf; lf=$(command -v linkfinder || command -v LinkFinder.py)
        log_message "[+] Running LinkFinder (endpoint extraction)..." "$BLUE"
        for jf in $files; do "$lf" -i "$jf" -o cli >> "$out_dir/_linkfinder.txt" 2>>"$CURRENT_LOG" || true; done
        [ -s "$out_dir/_linkfinder.txt" ] && { sort -u "$out_dir/_linkfinder.txt" -o "$out_dir/_linkfinder.txt"; printf "%-32s %s\n" "linkfinder_endpoints" "$(wc -l < "$out_dir/_linkfinder.txt")" >> "$summary"; }
    fi
    if command -v endext &>/dev/null; then
        log_message "[+] Running endext (endpoint extraction)..." "$BLUE"
        for jf in $files; do endext -f "$jf" >> "$out_dir/_endext.txt" 2>>"$CURRENT_LOG" || true; done
        [ -s "$out_dir/_endext.txt" ] && { sort -u "$out_dir/_endext.txt" -o "$out_dir/_endext.txt"; printf "%-32s %s\n" "endext_endpoints" "$(wc -l < "$out_dir/_endext.txt")" >> "$summary"; }
    fi

    log_message "[OK] JS analysis complete - open $out_dir/_FINDINGS.md (prioritized) or _SUMMARY.txt" "$GREEN"
}

# Apply -t/-e (TOOLS_TO_RUN/TOOLS_TO_EXCLUDE) to any "name:command" array -
# shared by passive-enum and crawling, so excluding a tool by name works the
# same way regardless of which phase it belongs to.
filter_tools_by_flags() {
    local -n src_ref="$1"
    local -n dest_ref="$2"

    for tool in "${src_ref[@]}"; do
        local tool_name="${tool%%:*}"
        tool_name=$(echo "$tool_name" | xargs)

        if [[ ${#TOOLS_TO_RUN[@]} -gt 0 && ! " ${TOOLS_TO_RUN[*]} " =~ " ${tool_name} " ]]; then
            continue
        fi
        if [[ " ${TOOLS_TO_EXCLUDE[*]} " =~ " ${tool_name} " ]]; then
            log_message "[i] Excluding tool: $tool_name" "$YELLOW"
            continue
        fi
        dest_ref+=("$tool")
    done
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
    local list_index="${2:-}"
    local list_total="${3:-}"
    local progress_tag=""
    [[ -n "$list_index" ]] && progress_tag="[$list_index/$list_total] "

    local timestamp
    timestamp=$(date '+%Y%m%d_%H%M%S')
    local domain_output_dir="$OUTPUT_DIR/${domain}_${timestamp}"
    LAST_DOMAIN_OUTPUT_DIR="$domain_output_dir"
    mkdir -p "$domain_output_dir/sources" "$domain_output_dir/bruteforce" "$domain_output_dir/crawling"
    local final_output="$domain_output_dir/final_subdomains.txt"
    ACTIVE_SUBDOMAINS="$domain_output_dir/active_subdomains.txt"
    CURRENT_LOG="$domain_output_dir/recogun.log"
    CURRENT_ERRORS="$domain_output_dir/.tool_errors"
    > "$CURRENT_LOG"
    > "$CURRENT_ERRORS"

    log_message "${progress_tag}[*] Processing domain: $domain" "$PURPLE"

    PREV_DIR=$(find_previous_run_dir "$domain" "$domain_output_dir")
    if [[ -n "$PREV_DIR" ]]; then
        log_message "[i] Comparing against previous scan: $PREV_DIR" "$CYAN"
    else
        log_message "[i] No previous scan found for $domain - this is the baseline run" "$YELLOW"
    fi

    # ---- Phase 1: passive subdomain enumeration (parallel) ----
    if ! phase_enabled enum; then
        log_message "[i] Enumeration phase skipped (--only)" "$YELLOW"
        # Seed the pipeline from the -f host list so downstream phases have
        # something to work on when enum didn't run.
        if [ -n "$INPUT_HOSTS_FILE" ]; then
            sort -u "$INPUT_HOSTS_FILE" > "$final_output"
            log_message "[i] Seeded $(count_unique_results "$final_output") hosts from $INPUT_HOSTS_FILE" "$CYAN"
        fi
    else
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
        "alienvault:curl -s $OTX_HDR 'https://otx.alienvault.com/api/v1/indicators/domain/$domain/passive_dns' | jq -r '.passive_dns[]?.hostname // empty' | sort -u"
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
    [[ -n "$VIRUSTOTAL_API_KEY" ]] && TOOLS+=("virustotal:curl -s 'https://www.virustotal.com/api/v3/domains/$domain/subdomains?limit=40' -H 'x-apikey: $VIRUSTOTAL_API_KEY' | jq -r '.data[]?.id // empty'") \
        || log_message "[i] Skipping virustotal - VIRUSTOTAL_API_KEY not set" "$YELLOW"
    [[ -n "$GITHUB_TOKEN" ]] && TOOLS+=("github-subdomains:github-subdomains -d $domain -t $GITHUB_TOKEN -raw") \
        || log_message "[i] Skipping github-subdomains - GITHUB_TOKEN not set" "$YELLOW"
    [[ -n "$GITLAB_TOKEN" ]] && TOOLS+=("gitlab-subdomains:gitlab-subdomains -d $domain -t $GITLAB_TOKEN") \
        || log_message "[i] Skipping gitlab-subdomains - GITLAB_TOKEN not set" "$YELLOW"
    command -v haktrails &>/dev/null && TOOLS+=("haktrails:echo \"$domain\" | haktrails subdomains")

    local FILTERED_TOOLS=()
    filter_tools_by_flags TOOLS FILTERED_TOOLS

    log_message "[*] Running ${#FILTERED_TOOLS[@]} passive sources (up to $PARALLEL_JOBS in parallel)..." "$BLUE"
    run_tools_parallel FILTERED_TOOLS "$domain_output_dir/sources"

    log_message "[+] Merging passive enumeration results..." "$BLUE"
    merge_results "$domain_output_dir/sources" "$final_output"
    apply_scope_filters "$final_output" "$domain_output_dir"
    log_message "[OK] Found $(count_unique_results "$final_output") unique subdomains from passive sources" "$GREEN"
    fi   # end enum phase

    # ---- Phase 1b: origin IP discovery (opt-in, -o) ----
    # Domain-level, not per-subdomain - a CDN/WAF setup is usually org-wide.
    # Gathers candidate origin IPs from passive sources + favicon hashing,
    # then confirms candidates with a direct GET (Host header spoofed via
    # --resolve) compared against the normal WAF-fronted response. No
    # payloads sent - this is fingerprinting/confirmation, not exploitation.
    if optin_phase_runs origin "$ORIGIN_IP_DISCOVERY"; then
        log_message "[*] Running origin IP discovery for $domain..." "$BLUE"
        mkdir -p "$domain_output_dir/origin_ip"

        # Preflight: these two tools read their OWN config, not config.env, and
        # fail opaquely (403 / "no keys found") if not set up. Warn once, up
        # front, with the exact fix - rather than let them error mid-run.
        if command -v uncover &>/dev/null && [ ! -f "$HOME/.config/uncover/provider-config.yaml" ]; then
            log_message "[!] uncover has no provider config - it will find nothing. Fix: see 'uncover setup' in the README (it reads ~/.config/uncover/, not config.env)." "$YELLOW"
        fi
        if [[ -n "$SHODAN_API_KEY" ]] && command -v shodan &>/dev/null; then
            if ! shodan info &>/dev/null; then
                log_message "[!] shodan CLI not authenticated (or plan lacks search) - shodan-cert/favicon will 403. Fix: run 'shodan init $SHODAN_API_KEY'." "$YELLOW"
            fi
        fi

        if command -v wafw00f &>/dev/null; then
            run_tool "wafw00f" "wafw00f https://$domain -a" "$domain_output_dir/origin_ip/waf_detection.txt"
        else
            log_message "[!] wafw00f not installed. Skipping WAF fingerprint." "$YELLOW"
        fi

        local ORIGIN_TOOLS=()
        if [[ -n "$VIRUSTOTAL_API_KEY" ]]; then
            # VT v3 (v2 /vtapi/v2 is dead - returns non-JSON, breaks jq). Key
            # goes in the x-apikey header, not the query string.
            ORIGIN_TOOLS+=("vt-resolutions:curl -s 'https://www.virustotal.com/api/v3/domains/$domain/resolutions?limit=40' -H 'x-apikey: $VIRUSTOTAL_API_KEY' | jq -r '.data[]?.attributes?.ip_address // empty'")
        fi
        # OTX passive_dns is the endpoint that actually returns resolved IPs
        # (the old url_list.result.urlworker.ip path was wrong and JSON-fragile).
        ORIGIN_TOOLS+=("otx-ips:curl -s $OTX_HDR 'https://otx.alienvault.com/api/v1/indicators/domain/$domain/passive_dns' | jq -r '.passive_dns[]?.address // empty' | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$'")
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
    if optin_phase_runs bruteforce "$BRUTEFORCE" && has_wildcard_dns "$domain"; then
        log_message "[!] Wildcard DNS detected on $domain - every bruteforce/permutation guess would resolve as a false positive (this is what causes 100k+ fake 'subdomains' and multi-hour httpx runs). Skipping bruteforce/permutation entirely for this domain." "$RED"
    elif optin_phase_runs bruteforce "$BRUTEFORCE"; then
        local resolvers_valid="$RESOLVERS_FILE"
        if [ -f "$RESOLVERS_FILE" ]; then
            resolvers_valid="$domain_output_dir/bruteforce/resolvers_valid.txt"
            validate_resolvers "$RESOLVERS_FILE" "$resolvers_valid"
        fi

        if [ ! -s "$final_output" ]; then
            log_message "[!] No seed subdomains for permutation - skipping dnsgen/alterx" "$YELLOW"
        else
            local PERM_TOOLS=()
            if command -v dnsgen &>/dev/null; then
                if [ -s "$PERMUTATION_WORDLIST" ]; then
                    PERM_TOOLS+=("dnsgen:dnsgen -w $PERMUTATION_WORDLIST $final_output")
                else
                    PERM_TOOLS+=("dnsgen:dnsgen $final_output")
                fi
            fi
            if command -v alterx &>/dev/null; then
                # -en enriches alterx's own curated word list rather than
                # replacing it. Only swap the word payload outright
                # (-pp word=file) if you explicitly passed -m yourself -
                # alterx's default list is purpose-built for its DSL
                # patterns and a generic wordlist isn't a clear upgrade.
                if $PERMUTATION_WORDLIST_CUSTOM && [ -s "$PERMUTATION_WORDLIST" ]; then
                    PERM_TOOLS+=("alterx:alterx -l $final_output -pp word=$PERMUTATION_WORDLIST")
                else
                    PERM_TOOLS+=("alterx:alterx -l $final_output -en")
                fi
            fi
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
        if ! command -v puredns &>/dev/null; then
            log_message "[!] puredns not installed - skipping wordlist bruteforce" "$YELLOW"
        elif [ ! -s "$resolvers_valid" ]; then
            log_message "[!] No validated resolvers - skipping wordlist bruteforce" "$YELLOW"
        elif [ ! -s "$WORDLIST_FILE" ]; then
            log_message "[!] Wordlist file ($WORDLIST_FILE) empty or missing - skipping wordlist bruteforce" "$YELLOW"
        else
            WORDLIST_TOOLS+=("puredns:puredns bruteforce $WORDLIST_FILE $domain --resolvers $resolvers_valid -q")
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
    if ! phase_enabled probe; then
        log_message "[i] Probe phase skipped (--only)" "$YELLOW"
        # Downstream phases (crawl/takeover/ports) still need a live-host list.
        # With probe skipped, seed it from -f (or the seeded final list).
        if [ ! -s "$ACTIVE_SUBDOMAINS" ]; then
            if [ -n "$INPUT_HOSTS_FILE" ]; then
                sort -u "$INPUT_HOSTS_FILE" > "$ACTIVE_SUBDOMAINS"
            elif [ -s "$final_output" ]; then
                sort -u "$final_output" > "$ACTIVE_SUBDOMAINS"
            fi
            [ -s "$ACTIVE_SUBDOMAINS" ] && log_message "[i] Using $(count_unique_results "$ACTIVE_SUBDOMAINS") hosts as-is (unprobed) for downstream phases" "$CYAN"
        fi
    elif [ -s "$final_output" ]; then
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
    if optin_phase_runs ports "$PORT_DISCOVERY" && [ -s "$ACTIVE_SUBDOMAINS" ]; then
        if command -v naabu &>/dev/null; then
            run_tool "naabu" "naabu -list $ACTIVE_SUBDOMAINS -passive -ec -cdn -c 5 -rate 500 -verify -silent" \
                "$domain_output_dir/naabu.txt"
        else
            log_message "[!] naabu not installed. Skipping passive port discovery." "$YELLOW"
        fi
    fi

    # ---- Phase 5: subdomain takeover check ----
    if phase_enabled takeover && [ -s "$ACTIVE_SUBDOMAINS" ]; then
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

    # ---- Phase 6: crawling (parallel, opt-in with -C) ----
    # If nothing upstream produced a host list (e.g. `crawl example.com` with no
    # enum/probe), seed it from the bare domain so passive crawlers still run.
    if optin_phase_runs crawl "$CRAWLING" && [ ! -s "$ACTIVE_SUBDOMAINS" ]; then
        printf '%s\n' "$domain" > "$ACTIVE_SUBDOMAINS"
        log_message "[i] No host list upstream - seeding crawl with the bare domain: $domain" "$CYAN"
    fi
    if ! optin_phase_runs crawl "$CRAWLING"; then
        log_message "[i] Crawling phase skipped (enable with -C)" "$YELLOW"
    elif [ -s "$ACTIVE_SUBDOMAINS" ]; then
        log_message "[*] Crawling $(count_unique_results "$ACTIVE_SUBDOMAINS") host(s) - passive URL discovery + JS collection" "$BLUE"

        # These process every active subdomain (can be hundreds), so they need
        # real internal concurrency, not just the outer parallel-tools job
        # pool - and a much longer timeout than quick API-based sources get.
        local CRAWL_TOOLS_ALL=()
        command -v waymore &>/dev/null && CRAWL_TOOLS_ALL+=("waymore:waymore -i $domain -mode U -oU /dev/stdout")
        command -v waybackurls &>/dev/null && CRAWL_TOOLS_ALL+=("waybackurls:cat $ACTIVE_SUBDOMAINS | xargs -P $PARALLEL_JOBS -I{} sh -c 'echo {} | waybackurls' 2>/dev/null")
        command -v gau &>/dev/null && CRAWL_TOOLS_ALL+=("gau-crawl:cat $ACTIVE_SUBDOMAINS | gau --threads $PARALLEL_JOBS")
        # urlfinder: passive URL discovery (PD), takes the host list as a file.
        command -v urlfinder &>/dev/null && CRAWL_TOOLS_ALL+=("urlfinder:urlfinder -list $ACTIVE_SUBDOMAINS -silent")
        command -v katana &>/dev/null && CRAWL_TOOLS_ALL+=("katana:katana -d 3 -jc -aff -fx -list $ACTIVE_SUBDOMAINS -c $PARALLEL_JOBS -silent")
        # hakrawler: active crawler, reads URLs from stdin; -subs keeps in-scope
        # subdomains, -u dedupes, -insecure tolerates bad TLS on recon targets.
        command -v hakrawler &>/dev/null && CRAWL_TOOLS_ALL+=("hakrawler:cat $ACTIVE_SUBDOMAINS | hakrawler -d 3 -t $PARALLEL_JOBS -subs -u -insecure")

        local CRAWL_TOOLS=()
        filter_tools_by_flags CRAWL_TOOLS_ALL CRAWL_TOOLS

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

            # Final crawl status readout.
            log_message "[=] Crawl results: $(count_unique_results "$crawl_final") URLs | $(count_unique_results "$domain_output_dir/crawling/javascript_files.txt") JS files | $(count_unique_results "$domain_output_dir/crawling/api_endpoints.txt") API endpoints" "$GREEN"

            # Auto-download JS content so the jsanalysis phase (and you) have
            # the actual files, not just URLs. Parallel, capped, deduped by a
            # safe filename derived from the URL.
            download_js_files "$domain_output_dir/crawling/javascript_files.txt" "$domain_output_dir/js_files"

            local urls_for_tagging="$crawl_final"
            if command -v uro &>/dev/null; then
                log_message "[+] Filtering URLs with uro..." "$BLUE"
                uro < "$crawl_final" > "$domain_output_dir/crawling/filtered_urls.txt"
                log_message "[OK] Filtered to $(count_unique_results "$domain_output_dir/crawling/filtered_urls.txt") unique URLs" "$GREEN"
                urls_for_tagging="$domain_output_dir/crawling/filtered_urls.txt"
            fi

            # Categorize parameterized URLs by likely vuln class with gf -
            # classification only, no payloads are sent. One file per pattern,
            # named <pattern>-param.txt (e.g. xss-param.txt, sqli-param.txt).
            if command -v gf &>/dev/null && [ -s "$urls_for_tagging" ]; then
                log_message "[+] Tagging parameterized URLs with gf..." "$BLUE"
                local gf_dir="$domain_output_dir/crawling/gf"
                mkdir -p "$gf_dir"

                # Only run patterns the user actually has installed in ~/.gf.
                local available_patterns
                available_patterns=$(gf -list 2>/dev/null)

                # Vuln-class patterns of interest, mapped to friendly filenames.
                # gf pattern name  ->  output file stem
                local -a GF_PATTERNS=(
                    "xss|xss"
                    "sqli|sqli"
                    "lfi|lfi"
                    "rce|rce"
                    "idor|idor"
                    "ssrf|ssrf"
                    "ssti|ssti"
                    "redirect|open-redirect"
                    "interestingparams|interesting-params"
                    "interestingEXT|interesting-ext"
                    "debug_logic|debug-logic"
                )
                local tagged=0 pat_entry pat stem outf
                for pat_entry in "${GF_PATTERNS[@]}"; do
                    pat="${pat_entry%%|*}"
                    stem="${pat_entry#*|}"
                    # Skip patterns this box doesn't have installed.
                    printf '%s\n' "$available_patterns" | grep -qxF "$pat" || continue
                    outf="$gf_dir/${stem}-param.txt"
                    gf "$pat" < "$urls_for_tagging" 2>>"$CURRENT_LOG" | sort -u > "$outf"
                    if [ -s "$outf" ]; then
                        log_message "    [gf] ${stem}-param.txt: $(count_unique_results "$outf") URLs" "$CYAN"
                        tagged=$((tagged + 1))
                    else
                        rm -f "$outf"
                    fi
                done
                if [ "$tagged" -eq 0 ]; then
                    log_message "[!] gf produced no tagged URLs (no matching patterns in ~/.gf, or no param URLs). Install patterns: https://github.com/1ndianl33t/Gf-Patterns" "$YELLOW"
                fi
            elif ! command -v gf &>/dev/null; then
                log_message "[i] gf not installed - skipping parameter tagging (install: go install github.com/tomnomnom/gf@latest + Gf-Patterns)" "$YELLOW"
            fi
        else
            log_message "[!] No crawling results found" "$YELLOW"
        fi
    fi

    # ---- Phase 6a: parameter discovery with Arjun (opt-in via `params`) ----
    # ACTIVE: Arjun sends real requests to probe endpoints for hidden query/body
    # parameters, so it is gated behind its own opt-in phase (not run on every
    # crawl). Input priority: this run's filtered/crawled URLs, then a -f list.
    if optin_phase_runs params "$PARAM_DISCOVERY"; then
        local arjun_input=""
        if [ -s "$domain_output_dir/crawling/filtered_urls.txt" ]; then
            arjun_input="$domain_output_dir/crawling/filtered_urls.txt"
        elif [ -s "$domain_output_dir/crawling/final_crawling_results.txt" ]; then
            arjun_input="$domain_output_dir/crawling/final_crawling_results.txt"
        elif [ -n "$INPUT_HOSTS_FILE" ] && [ -s "$INPUT_HOSTS_FILE" ]; then
            arjun_input="$INPUT_HOSTS_FILE"
        fi

        if ! command -v arjun &>/dev/null; then
            log_message "[!] arjun not installed - skipping parameter discovery" "$YELLOW"
        elif [ -z "$arjun_input" ]; then
            log_message "[!] params: no URLs to probe (run with crawl, or supply -f <urls.txt>)" "$YELLOW"
        else
            local arjun_out="$domain_output_dir/parameters.json"
            log_message "[*] Arjun: probing $(count_unique_results "$arjun_input") URL(s) for hidden parameters (active)..." "$BLUE"
            $VERBOSE && log_message "    -> arjun -i $arjun_input -oJ $arjun_out -t $PARALLEL_JOBS --stable" "$CYAN"
            if timeout "$CRAWL_TIMEOUT_SECONDS" arjun -i "$arjun_input" -oJ "$arjun_out" -t "$PARALLEL_JOBS" --stable 2>> "$CURRENT_LOG"; then
                if [ -s "$arjun_out" ]; then
                    log_message "[OK] Arjun wrote discovered parameters to parameters.json" "$GREEN"
                else
                    log_message "[!] Arjun found no parameters" "$YELLOW"
                    rm -f "$arjun_out"
                fi
            else
                log_message "[X] Arjun failed or timed out" "$RED"
            fi
        fi
    fi

    # ---- Phase 6b: JS intelligence analysis (opt-in via --only jsanalysis) ----
    # Offline extraction over downloaded JS. Sources of JS, in priority order:
    # this run's js_files/ (from crawl), or -f as a JS-URL list to download now.
    if phase_enabled jsanalysis; then
        local js_src_dir="$domain_output_dir/js_files"
        # Standalone mode: --only jsanalysis -f jsurls.txt (no crawl this run).
        if [ ! -d "$js_src_dir" ] || [ -z "$(find "$js_src_dir" -maxdepth 1 -name '*.js' 2>/dev/null)" ]; then
            if [ -n "$INPUT_HOSTS_FILE" ]; then
                log_message "[*] jsanalysis: downloading JS from $INPUT_HOSTS_FILE..." "$BLUE"
                download_js_files "$INPUT_HOSTS_FILE" "$js_src_dir"
            fi
        fi
        if [ -d "$js_src_dir" ] && [ -n "$(find "$js_src_dir" -maxdepth 1 -name '*.js' 2>/dev/null)" ]; then
            analyze_js "$js_src_dir" "$domain_output_dir/js_analysis"
            # Historical diff: which finding VALUES are NEW vs the previous scan.
            # Category files now live under findings/ and carry a "value<TAB>source"
            # format, so we diff on the value column only (ignore # header lines
            # and source attribution, which change run-to-run without the finding
            # itself being new).
            local cur_find="$domain_output_dir/js_analysis/findings"
            local prev_find="$PREV_DIR/js_analysis/findings"
            if [[ -n "$PREV_DIR" && -d "$prev_find" ]]; then
                mkdir -p "$domain_output_dir/js_analysis/new"
                for cf in "$cur_find"/*.txt; do
                    [ -f "$cf" ] || continue
                    local bn; bn=$(basename "$cf")
                    local newf="$domain_output_dir/js_analysis/new/$bn"
                    if [ -f "$prev_find/$bn" ]; then
                        comm -13 \
                            <(grep -v '^#' "$prev_find/$bn" 2>/dev/null | cut -f1 | sort -u) \
                            <(grep -v '^#' "$cf" 2>/dev/null | cut -f1 | sort -u) > "$newf"
                    else
                        grep -v '^#' "$cf" 2>/dev/null | cut -f1 | sort -u > "$newf"
                    fi
                    [ -s "$newf" ] || rm -f "$newf"
                done
                [ -n "$(ls -A "$domain_output_dir/js_analysis/new" 2>/dev/null)" ] && \
                    log_message "[i] New JS findings since last scan in js_analysis/new/" "$CYAN"
            fi
        else
            log_message "[!] jsanalysis: no JS files available (run with crawl, or supply -f <jsurls.txt>)" "$YELLOW"
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

        if [ -d "$domain_output_dir/crawling/gf" ] && [ "$(ls -A "$domain_output_dir/crawling/gf" 2>/dev/null)" ]; then
            echo "=== Parameter Triage (gf) ==="
            for f in "$domain_output_dir/crawling/gf"/*.txt; do
                echo "$(basename "$f" .txt): $(count_unique_results "$f") URLs"
            done
            echo ""
        fi

        if [ -s "$domain_output_dir/parameters.json" ]; then
            echo "=== Hidden Parameters (Arjun) ==="
            echo "See parameters.json"
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

    # -O: also drop this domain's primary product into a shared folder as
    # <root>.txt. "Primary product" = the deepest phase that produced output:
    # crawl URLs > active hosts > all subdomains.
    if [ -n "$OUTPUT_COLLECT_DIR" ]; then
        local collect_src=""
        if [ -s "$domain_output_dir/crawling/final_crawling_results.txt" ]; then
            collect_src="$domain_output_dir/crawling/final_crawling_results.txt"
        elif [ -s "$ACTIVE_SUBDOMAINS" ]; then
            collect_src="$ACTIVE_SUBDOMAINS"
        elif [ -s "$final_output" ]; then
            collect_src="$final_output"
        fi
        if [ -n "$collect_src" ]; then
            local root
            root=$(root_domain "$domain")
            [ -z "$root" ] && root="$domain"
            cp "$collect_src" "$OUTPUT_COLLECT_DIR/${root}.txt"
            log_message "[+] Collected $(count_unique_results "$collect_src") lines -> $OUTPUT_COLLECT_DIR/${root}.txt" "$GREEN"
        fi
    fi

    echo ""
    log_message "${progress_tag}=== SCAN SUMMARY: $domain ===" "$CYAN"
    log_message "Total Subdomains: $total_subs" "$CYAN"
    log_message "Active Subdomains: $active_subs" "$CYAN"
    if [ -s "$domain_output_dir/takeovers.txt" ]; then
        log_message "Takeovers: FOUND - see takeovers.txt" "$RED"
    fi
    if [ ${#TOOL_ERRORS[@]} -gt 0 ]; then
        log_message "Failed Tools: ${#TOOL_ERRORS[@]}" "$RED"
    fi
    log_message "${progress_tag}[DONE] $domain" "$GREEN"
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
    _dep_check "Crawling" gau ""
    _dep_check "Crawling" urlfinder ""
    _dep_check "Crawling" katana ""
    _dep_check "Crawling" hakrawler ""
    _dep_check "Crawling" uro ""
    _dep_check "Crawling" gf ""

    _dep_check "Parameter discovery (params)" arjun ""

    # JS analysis works with zero external tools (built-in regex engine), but
    # these add maintained rule sets / extractors when present.
    _dep_check "JS analysis (optional boosters)" trufflehog ""
    _dep_check "JS analysis (optional boosters)" secretfinder ""
    _dep_check "JS analysis (optional boosters)" linkfinder ""
    _dep_check "JS analysis (optional boosters)" endext ""

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

# Check origin/main for new commits. Interactive (-t 0, i.e. a real terminal)
# gets a y/n prompt; anything else (cron, piped, CI) skips the prompt
# entirely so an automated run never hangs waiting for input on stdin that
# will never arrive. Silent no-op if this isn't a git checkout or the
# network/fetch fails - update checking must never block a scan.
check_for_updates() {
    local explicit="${1:-false}"

    if [ ! -d "$SCRIPT_DIR/.git" ]; then
        $explicit && log_message "[!] Not a git checkout - can't check for updates." "$YELLOW"
        return
    fi

    local local_hash remote_hash behind_count
    local_hash=$(git -C "$SCRIPT_DIR" rev-parse HEAD 2>/dev/null)
    if ! timeout 10 git -C "$SCRIPT_DIR" fetch --quiet origin main 2>/dev/null; then
        $explicit && log_message "[!] Could not reach origin - skipping update check." "$YELLOW"
        return
    fi
    remote_hash=$(git -C "$SCRIPT_DIR" rev-parse origin/main 2>/dev/null)

    if [[ -z "$local_hash" || -z "$remote_hash" || "$local_hash" == "$remote_hash" ]]; then
        $explicit && log_message "[OK] Already up to date." "$GREEN"
        return
    fi

    behind_count=$(git -C "$SCRIPT_DIR" rev-list --count "HEAD..origin/main" 2>/dev/null)
    log_message "[i] Update available: $behind_count new commit(s) on origin/main" "$YELLOW"

    if [ -t 0 ]; then
        read -r -p "Update now? [y/N] " answer
        if [[ "$answer" =~ ^[Yy]$ ]]; then
            if git -C "$SCRIPT_DIR" pull --ff-only origin main; then
                log_message "[OK] Updated. Re-run your command to use the new version." "$GREEN"
            else
                log_message "[!] Update failed (local changes or diverged history?) - continuing with current version." "$RED"
            fi
            exit 0
        fi
    else
        log_message "[i] Non-interactive session - skipping update prompt. Run with -u to update manually." "$YELLOW"
    fi
}

show_usage() {
    echo -e "${BLUE}RecoGun - Automated Reconnaissance Tool${RESET}  by $OPERATOR"
    echo ""
    echo -e "${GREEN}Usage:${RESET}  recogun <command> <target> [options]"
    echo ""
    echo -e "${GREEN}Commands:${RESET}"
    echo "  scan <target>       Default recon: enum -> probe -> takeover"
    echo "  full <target>       Everything: enum, bruteforce, probe, origin, ports, takeover, crawl, params"
    echo "  enum <target>       Only find subdomains"
    echo "  probe <target>      Only enum + httpx probe (which subdomains are live)"
    echo "  crawl <target>      Crawl (waymore/wayback/gau/urlfinder/katana/hakrawler) + JS analysis"
    echo "  js <jsurls.txt>     Only JS intelligence analysis on a list of .js URLs"
    echo "  params <target>     Crawl, then probe URLs for hidden parameters (Arjun, ACTIVE)"
    echo "  origin <target>     Only origin-IP-behind-WAF discovery"
    echo "  ports <target>      Only passive port discovery (naabu -passive)"
    echo "  takeover <target>   Only subdomain-takeover checks"
    echo "  run <phases> <target>   Custom combo, e.g. 'run enum,crawl example.com'"
    echo "  check               Report which tools/API keys are available, then exit"
    echo "  update              Check for a newer RecoGun version, then exit"
    echo ""
    echo -e "${GREEN}Target${RESET} is auto-detected:"
    echo "  a domain            example.com"
    echo "  a file of domains   domains.txt   (bare roots, one per line -> enumerated)"
    echo "  a file of hosts     hosts.txt     (full subdomains -> split by root, fed straight in)"
    echo ""
    echo -e "${GREEN}Options:${RESET}"
    echo "  -o <dir>            Collect each domain's main output as <root>.txt in this folder"
    echo "  -j <n>              Max parallel tool jobs (default: 8)"
    echo "  -v                  Verbose - log the actual command run per tool (keys redacted)"
    echo "  --scope <file>      Include-only scope (exact subs or *.domain.tld, one per line)"
    echo "  --oos <file>        Out-of-scope list (same format) - dropped from results"
    echo "  --wordlist <file>   Custom bruteforce wordlist (default: bundled)"
    echo "  --resolvers <file>  Custom resolvers list (default: bundled)"
    echo "  --perms <file>      Custom permutation wordlist (default: bundled)"
    echo "  --exclude <t1,t2>   Skip these tools by name (e.g. --exclude katana,amass)"
    echo ""
    echo -e "${GREEN}Examples:${RESET}"
    echo "  recogun scan example.com"
    echo "  recogun full example.com -v"
    echo "  recogun crawl hosts.txt -o out/          # split by root, one out/<root>.txt each"
    echo "  recogun enum domains.txt -o subs/"
    echo "  recogun run enum,takeover example.com"
    echo "  recogun origin example.com"
    echo "  recogun js js_urls.txt                   # analyze a list of JS file URLs"
    echo "  recogun crawl example.com                # crawl then auto-analyze its JS"
}

# Translate a subcommand into the explicit phase list the engine runs. The
# engine is driven entirely by ONLY_PHASES, so every command just sets it.
set_phases_for_command() {
    case "$1" in
        scan)     ONLY_PHASES=(enum probe takeover) ;;
        full)     ONLY_PHASES=(enum bruteforce probe origin ports takeover crawl jsanalysis params) ;;
        enum)     ONLY_PHASES=(enum) ;;
        probe)    ONLY_PHASES=(enum probe) ;;
        crawl)    ONLY_PHASES=(crawl jsanalysis) ;;
        origin)   ONLY_PHASES=(origin) ;;
        ports)    ONLY_PHASES=(enum probe ports) ;;
        takeover) ONLY_PHASES=(enum probe takeover) ;;
        js)       ONLY_PHASES=(jsanalysis) ;;
        params)   ONLY_PHASES=(crawl params) ;;
        *)        return 1 ;;
    esac
}

# Guess whether a target string is a domain, a file of bare root domains, or
# a file of full hosts. Files are classified by sampling their lines: if most
# lines have 3+ dot-separated labels (sub.dom.tld) they're hosts; if 2
# (dom.tld) they're root domains.
detect_target_kind() {
    local target="$1"
    if [ ! -f "$target" ]; then
        echo "domain"; return
    fi
    local sample host_like=0 total=0
    while IFS= read -r line && [ "$total" -lt 20 ]; do
        line="$(echo "$line" | xargs)"
        [[ -z "$line" || "$line" == \#* ]] && continue
        total=$((total + 1))
        local root
        root=$(root_domain "$line")
        # If the line has more labels than its own registered root, it's a host.
        [[ -n "$root" && "$line" != "$root" ]] && host_like=$((host_like + 1))
    done < "$target"
    if [ "$total" -eq 0 ]; then
        echo "domainfile"   # empty-ish; treat as domain list, harmless
    elif [ "$host_like" -gt $((total / 2)) ]; then
        echo "hostfile"
    else
        echo "domainfile"
    fi
}

# --- Parse: first positional is the command, second is the target (unless
# the command is check/update which take neither). Remaining args are options.
COMMAND="${1:-}"
[ $# -gt 0 ] && shift

case "$COMMAND" in
    ""|-h|--help|help)
        show_usage; exit 0 ;;
    check)
        check_dependencies; exit 0 ;;
    update)
        check_for_updates true; exit 0 ;;
    scan|full|enum|probe|crawl|origin|ports|takeover|js|params)
        set_phases_for_command "$COMMAND"
        TARGET="${1:-}"; [ $# -gt 0 ] && shift ;;
    run)
        RUN_PHASES="${1:-}"; [ $# -gt 0 ] && shift
        IFS=',' read -ra ONLY_PHASES <<< "$(echo "$RUN_PHASES" | tr -d ' ')"
        TARGET="${1:-}"; [ $# -gt 0 ] && shift ;;
    *)
        echo -e "${RED}Error: unknown command '$COMMAND'${RESET}"
        show_usage; exit 1 ;;
esac

# Enable the opt-in booleans for whatever phases the command selected, so the
# engine's optin_phase_runs() checks pass. (In --only/ONLY_PHASES mode these
# booleans aren't strictly required, but setting them keeps behavior obvious.)
for ph in "${ONLY_PHASES[@]}"; do
    case "$ph" in
        bruteforce) BRUTEFORCE=true ;;
        ports)      PORT_DISCOVERY=true ;;
        origin)     ORIGIN_IP_DISCOVERY=true ;;
        crawl)      CRAWLING=true ;;
        params)     PARAM_DISCOVERY=true ;;
    esac
done

# --- Remaining options (order-independent, long + short) ---
while [ $# -gt 0 ]; do
    case "$1" in
        -o)            OUTPUT_COLLECT_DIR="$2"; shift 2 ;;
        -j)            PARALLEL_JOBS="$2"; shift 2 ;;
        -v)            VERBOSE=true; shift ;;
        --scope)       INCLUDE_FILE="$2"; shift 2 ;;
        --oos)         OOS_FILE="$2"; shift 2 ;;
        --wordlist)    WORDLIST_FILE="$2"; shift 2 ;;
        --resolvers)   RESOLVERS_FILE="$2"; shift 2 ;;
        --perms)       PERMUTATION_WORDLIST="$2"; PERMUTATION_WORDLIST_CUSTOM=true; shift 2 ;;
        --exclude)     IFS=',' read -ra TOOLS_TO_EXCLUDE <<< "$(echo "$2" | tr -d ' ')"; shift 2 ;;
        *)
            echo -e "${RED}Error: unknown option '$1'${RESET}"
            show_usage; exit 1 ;;
    esac
done

# --- Validate ---
if [ -z "$TARGET" ]; then
    echo -e "${RED}Error: '$COMMAND' needs a target (domain, domains file, or hosts file)${RESET}"
    show_usage; exit 1
fi

VALID_PHASES=" enum bruteforce probe origin ports takeover crawl jsanalysis params "
for ph in "${ONLY_PHASES[@]}"; do
    if [[ "$VALID_PHASES" != *" $ph "* ]]; then
        echo -e "${RED}Error: unknown phase '$ph'. Valid: enum, bruteforce, probe, origin, ports, takeover, crawl, jsanalysis${RESET}"
        exit 1
    fi
done

$BRUTEFORCE && [ ! -f "$WORDLIST_FILE" ] && { echo -e "${RED}Error: Wordlist file '$WORDLIST_FILE' not found${RESET}"; exit 1; }
$BRUTEFORCE && [ ! -f "$RESOLVERS_FILE" ] && { echo -e "${RED}Error: Resolvers file '$RESOLVERS_FILE' not found${RESET}"; exit 1; }
$PERMUTATION_WORDLIST_CUSTOM && [ ! -f "$PERMUTATION_WORDLIST" ] && { echo -e "${RED}Error: Permutation wordlist '$PERMUTATION_WORDLIST' not found${RESET}"; exit 1; }
[ -n "$INCLUDE_FILE" ] && [ ! -f "$INCLUDE_FILE" ] && { echo -e "${RED}Error: Scope file '$INCLUDE_FILE' not found${RESET}"; exit 1; }
[ -n "$OOS_FILE" ] && [ ! -f "$OOS_FILE" ] && { echo -e "${RED}Error: OOS file '$OOS_FILE' not found${RESET}"; exit 1; }

# --- Resolve target into a run mode ---
TARGET_KIND=$(detect_target_kind "$TARGET")

# Phases that consume a host/URL list rather than producing one. jsanalysis
# is included: with no crawl in the run it needs a JS-URL file as its target.
needs_hosts=false
for ph in crawl takeover ports jsanalysis; do
    [[ " ${ONLY_PHASES[*]} " == *" $ph "* ]] && needs_hosts=true
done
have_producer=false
{ [[ " ${ONLY_PHASES[*]} " == *" enum "* ]] || [[ " ${ONLY_PHASES[*]} " == *" probe "* ]] || [[ " ${ONLY_PHASES[*]} " == *" crawl "* ]]; } && have_producer=true

mkdir -p "$OUTPUT_DIR"
[ -n "$OUTPUT_COLLECT_DIR" ] && mkdir -p "$OUTPUT_COLLECT_DIR"

check_for_updates

echo -e "${PURPLE}"
echo "  +=========================================+"
echo "  |              RecoGun v6.5                |"
echo "  |    Automated Reconnaissance Tool         |"
echo "  |                 by $OPERATOR                 |"
echo "  +=========================================+"
echo -e "${RESET}"
echo -e "${CYAN}Command: ${RESET}$COMMAND    ${CYAN}Phases: ${RESET}${ONLY_PHASES[*]}"
echo -e "${CYAN}Target : ${RESET}$TARGET (${TARGET_KIND})"
[ -n "$OUTPUT_COLLECT_DIR" ] && echo -e "${CYAN}Collect: ${RESET}$OUTPUT_COLLECT_DIR/<root>.txt"
echo ""

# --- Dispatch ---
case "$TARGET_KIND" in
    domain)
        # A host-consuming-only command against a bare domain has no producer
        # and no host file - can't work.
        if $needs_hosts && ! $have_producer; then
            echo -e "${RED}Error: '$COMMAND' needs live hosts but has no way to get them for a single domain. Give it a hosts file instead, or use 'scan'/'full'.${RESET}"
            exit 1
        fi
        process_domain "$TARGET"
        ;;

    hostfile)
        # Split the host file by root domain, feed each root's hosts straight in.
        log_message "[*] Splitting $(count_unique_results "$TARGET") hosts by root domain..." "$BLUE"
        SPLIT_DIR=$(mktemp -d)
        while IFS= read -r host || [[ -n "$host" ]]; do
            host="$(echo "$host" | xargs)"
            [[ -z "$host" || "$host" == \#* ]] && continue
            root=$(root_domain "$host"); [ -z "$root" ] && continue
            echo "$host" >> "$SPLIT_DIR/$root"
        done < "$TARGET"
        mapfile -t ROOTS < <(cd "$SPLIT_DIR" && ls -1 | sort)
        total_domains=${#ROOTS[@]}
        log_message "[*] $total_domains root domain(s)" "$BLUE"
        idx=0; tko=()
        for root in "${ROOTS[@]}"; do
            idx=$((idx + 1))
            INPUT_HOSTS_FILE="$SPLIT_DIR/$root"
            process_domain "$root" "$idx" "$total_domains"
            [ -s "$LAST_DOMAIN_OUTPUT_DIR/takeovers.txt" ] && tko+=("$root")
            echo ""
        done
        rm -rf "$SPLIT_DIR"
        echo -e "${GREEN}  === ALL $total_domains ROOT DOMAIN(S) COMPLETE ===${RESET}"
        [ ${#tko[@]} -gt 0 ] && log_message "Takeovers found on: ${tko[*]}" "$RED"
        [ -n "$OUTPUT_COLLECT_DIR" ] && log_message "Output collected in: $OUTPUT_COLLECT_DIR" "$GREEN"
        ;;

    domainfile)
        # A file of bare root domains: enumerate each. If the command is
        # host-consuming-only (no producer), it has no hosts per domain.
        if $needs_hosts && ! $have_producer; then
            echo -e "${RED}Error: '$COMMAND' needs live hosts, but '$TARGET' is a list of bare domains with no enum/probe to find them. Use a hosts file, or 'scan'/'full'.${RESET}"
            exit 1
        fi
        total_domains=$(grep -cv '^[[:space:]]*\(#\|$\)' "$TARGET")
        log_message "[*] Processing $total_domains domain(s) from $TARGET" "$BLUE"
        idx=0; tko=(); errs=()
        while IFS= read -r domain || [[ -n "$domain" ]]; do
            [[ -z "$domain" || "$domain" =~ ^[[:space:]]*# ]] && continue
            idx=$((idx + 1)); domain="$(echo "$domain" | xargs)"
            process_domain "$domain" "$idx" "$total_domains"
            [ -s "$LAST_DOMAIN_OUTPUT_DIR/takeovers.txt" ] && tko+=("$domain")
            [ -s "$LAST_DOMAIN_OUTPUT_DIR/.tool_errors" ] && errs+=("$domain")
            echo ""
        done < "$TARGET"
        echo -e "${GREEN}  === ALL $total_domains DOMAIN(S) COMPLETE ===${RESET}"
        [ ${#tko[@]} -gt 0 ] && log_message "Takeovers found on: ${tko[*]}" "$RED"
        [ ${#errs[@]} -gt 0 ] && log_message "Domains with tool errors: ${errs[*]}" "$YELLOW"
        ;;
esac

log_message "[OK] RecoGun done!" "$GREEN"
