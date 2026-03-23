#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "Usage: $0 <before-summary.json> <after-summary.json>"
  exit 2
fi

BEFORE="$1"
AFTER="$2"

node - "$BEFORE" "$AFTER" <<'NODE'
const fs = require('fs');
const before = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const after = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));

function delta(a, b) {
  return b - a;
}

const result = {
  service_name: after.service_name || before.service_name,
  before_label: before.label,
  after_label: after.label,
  budget_ok: Boolean(after.budget_ok),
  dependency: {
    before_high_critical: Number(before.dependency_scan.high || 0) + Number(before.dependency_scan.critical || 0),
    after_high_critical: Number(after.dependency_scan.high || 0) + Number(after.dependency_scan.critical || 0),
  },
  sast: {
    before_total: Number(before.sast_scan.findings_total || 0),
    after_total: Number(after.sast_scan.findings_total || 0),
  },
  container: {
    before_total: Number(before.container_scan.vulnerabilities_high_critical || 0) + Number(before.container_scan.misconfig_high_critical || 0),
    after_total: Number(after.container_scan.vulnerabilities_high_critical || 0) + Number(after.container_scan.misconfig_high_critical || 0),
  }
};

result.dependency.delta = delta(result.dependency.before_high_critical, result.dependency.after_high_critical);
result.sast.delta = delta(result.sast.before_total, result.sast.after_total);
result.container.delta = delta(result.container.before_total, result.container.after_total);

result.vulnerability_removed =
  result.dependency.after_high_critical <= result.dependency.before_high_critical &&
  result.container.after_total <= result.container.before_total;

console.log(JSON.stringify(result, null, 2));
NODE
