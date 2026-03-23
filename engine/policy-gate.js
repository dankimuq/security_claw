#!/usr/bin/env node
const fs = require('fs');

if (process.argv.length < 3) {
  console.error('Usage: node engine/policy-gate.js <summary-or-diff.json>');
  process.exit(2);
}

const input = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));

if ('vulnerability_removed' in input) {
  const pass = Boolean(input.budget_ok) && Boolean(input.vulnerability_removed);
  if (!pass) {
    console.error('Policy gate failed: patch validation did not satisfy criteria.');
    process.exit(1);
  }
  console.log('Policy gate passed: patch validation successful.');
  process.exit(0);
}

const depRisk = Number(input.dependency_scan.high || 0) + Number(input.dependency_scan.critical || 0);
const containerRisk = Number(input.container_scan.vulnerabilities_high_critical || 0) + Number(input.container_scan.misconfig_high_critical || 0);

const pass = Boolean(input.budget_ok) && depRisk === 0 && containerRisk === 0;
if (!pass) {
  console.error('Policy gate failed: baseline risk threshold exceeded.');
  process.exit(1);
}

console.log('Policy gate passed: baseline threshold met.');
