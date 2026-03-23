#!/usr/bin/env bash
set -uo pipefail

if [ "$#" -lt 2 ]; then
  echo "Usage: $0 <service-profile.json> <label>"
  exit 2
fi

PROFILE_PATH="$1"
LABEL="$2"
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

PROFILE_JSON="$(node -e 'const fs=require("fs");const p=process.argv[1];const obj=JSON.parse(fs.readFileSync(p,"utf8"));process.stdout.write(JSON.stringify(obj));' "$PROFILE_PATH")"

get_json_value() {
  local key="$1"
  node -e 'const obj=JSON.parse(process.argv[1]);const key=process.argv[2];const v=obj[key];if(v===undefined||v===null){process.exit(1)};process.stdout.write(String(v));' "$PROFILE_JSON" "$key"
}

SERVICE_NAME="$(get_json_value service_name)"
REPO_PATH_RAW="$(get_json_value repo_path)"
BUDGET_SEC="$(get_json_value time_budget_sec)"

get_command_spec() {
  local key="$1"
  node -e 'const obj=JSON.parse(process.argv[1]); const key=process.argv[2]; const value=obj[key]; if(!value || typeof value.command !== "string" || !Array.isArray(value.args)){ process.exit(1); } process.stdout.write(JSON.stringify(value));' "$PROFILE_JSON" "$key"
}

DEPENDENCY_SPEC="$(get_command_spec dependency_scan)"
SAST_SPEC="$(get_command_spec sast_scan)"
CONTAINER_SPEC="$(get_command_spec container_scan)"

if [ "$REPO_PATH_RAW" = "." ]; then
  REPO_PATH="$ROOT_DIR"
else
  REPO_PATH="$REPO_PATH_RAW"
fi

REPORT_DIR="$ROOT_DIR/reports/$LABEL"
mkdir -p "$REPORT_DIR"

START_TS=$(date +%s)
END_TS=$((START_TS + BUDGET_SEC))

log() { printf "[%s] %s\n" "$(date '+%H:%M:%S')" "$*"; }
left() { echo $((END_TS - $(date +%s))); }

run_step() {
  local name="$1"
  local spec_json="$2"
  local out_file="$3"
  local err_file="$4"
  local rc_file="$5"

  local remain
  remain=$(left)
  if [ "$remain" -le 0 ]; then
    echo 124 > "$rc_file"
    log "TIME_BUDGET_EXCEEDED before: $name"
    return 124
  fi

  log "START: $name (remaining ${remain}s)"
  (
    cd "$REPO_PATH" || exit 2
    node "$ROOT_DIR/engine/run-command.cjs" "$spec_json" "$REPO_PATH" > "$out_file" 2> "$err_file"
  )
  local rc=$?
  echo "$rc" > "$rc_file"
  log "END: $name (rc=$rc)"
  return 0
}

run_step "dependency_scan" "$DEPENDENCY_SPEC" "$REPORT_DIR/01_dependency.json" "$REPORT_DIR/01_dependency.err" "$REPORT_DIR/01_dependency.exit"
run_step "sast_scan" "$SAST_SPEC" "$REPORT_DIR/02_sast.json" "$REPORT_DIR/02_sast.err" "$REPORT_DIR/02_sast.exit"
run_step "container_scan" "$CONTAINER_SPEC" "$REPORT_DIR/03_container.json" "$REPORT_DIR/03_container.err" "$REPORT_DIR/03_container.exit"

TOTAL_ELAPSED=$(( $(date +%s) - START_TS ))

node - "$SERVICE_NAME" "$LABEL" "$REPORT_DIR" "$TOTAL_ELAPSED" "$BUDGET_SEC" <<'NODE'
const fs = require('fs');
const [serviceName, label, reportDir, elapsedStr, budgetStr] = process.argv.slice(2);

function readText(path, fallback = '') {
  try { return fs.readFileSync(path, 'utf8').trim(); } catch { return fallback; }
}
function readJSON(path) {
  try { return JSON.parse(fs.readFileSync(path, 'utf8')); } catch { return {}; }
}

const dependencyRc = Number(readText(`${reportDir}/01_dependency.exit`, '1'));
const sastRc = Number(readText(`${reportDir}/02_sast.exit`, '1'));
const containerRc = Number(readText(`${reportDir}/03_container.exit`, '1'));

const dep = readJSON(`${reportDir}/01_dependency.json`);
const sast = readJSON(`${reportDir}/02_sast.json`);
const cont = readJSON(`${reportDir}/03_container.json`);

const depV = (dep.metadata && dep.metadata.vulnerabilities) || {};
const semResults = sast.results || [];
const semBy = {};
for (const r of semResults) {
  const sev = (r.extra && r.extra.severity) || 'UNKNOWN';
  semBy[sev] = (semBy[sev] || 0) + 1;
}

let trivyVuln = 0;
let trivyMis = 0;
for (const r of (cont.Results || [])) {
  trivyVuln += (r.Vulnerabilities || []).length;
  trivyMis += (r.Misconfigurations || []).length;
}

const elapsed = Number(elapsedStr);
const budget = Number(budgetStr);
const summary = {
  service_name: serviceName,
  label,
  elapsed_sec: elapsed,
  budget_sec: budget,
  budget_ok: elapsed <= budget,
  dependency_scan: {
    exit_code: dependencyRc,
    high: Number(depV.high || 0),
    critical: Number(depV.critical || 0),
    total: Number(depV.total || 0)
  },
  sast_scan: {
    exit_code: sastRc,
    findings_total: semResults.length,
    by_severity: semBy
  },
  container_scan: {
    exit_code: containerRc,
    vulnerabilities_high_critical: trivyVuln,
    misconfig_high_critical: trivyMis
  }
};

fs.writeFileSync(`${reportDir}/summary.json`, JSON.stringify(summary, null, 2));
fs.writeFileSync(`${reportDir}/summary.txt`, Object.entries(summary).map(([k,v]) => `${k}=${typeof v === 'object' ? JSON.stringify(v) : v}`).join('\n') + '\n');
console.log(JSON.stringify(summary, null, 2));
NODE

log "DONE: $SERVICE_NAME ($LABEL) elapsed=${TOTAL_ELAPSED}s"
log "REPORT: $REPORT_DIR/summary.json"
