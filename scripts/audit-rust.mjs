#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

function fail(message) {
  console.error(`audit-rust: ${message}`);
  process.exit(1);
}

function isoDate(d) {
  return d.toISOString().slice(0, 10);
}

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, "..");
const policyPath = path.join(repoRoot, "security", "rustsec-policy.json");

if (!fs.existsSync(policyPath)) {
  fail(`missing policy file at ${policyPath}`);
}

const policy = JSON.parse(fs.readFileSync(policyPath, "utf8"));
const allow = new Map((policy.allow || []).map((entry) => [entry.id, entry]));
const maxReviewWindowDays = Number(policy?.metadata?.max_review_window_days ?? 45);
if (!Number.isFinite(maxReviewWindowDays) || maxReviewWindowDays < 1) {
  fail("metadata.max_review_window_days must be a positive integer");
}

let auditJson;
try {
  const raw = execFileSync("cargo", ["audit", "--json"], {
    cwd: repoRoot,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  });
  auditJson = JSON.parse(raw);
} catch (error) {
  const stdout = error?.stdout?.toString?.() || "";
  if (!stdout.trim()) {
    fail(`failed to execute cargo audit --json (${error.message})`);
  }
  try {
    auditJson = JSON.parse(stdout);
  } catch (parseError) {
    fail(`failed to parse cargo audit --json output (${parseError.message})`);
  }
}

const warnings = auditJson?.warnings || {};
const advisoryWarnings = [
  ...(warnings.unmaintained || []),
  ...(warnings.unsound || []),
  ...(warnings.notice || [])
];

const today = isoDate(new Date());
const maxReviewDate = (() => {
  const dt = new Date(`${today}T00:00:00Z`);
  dt.setUTCDate(dt.getUTCDate() + Math.trunc(maxReviewWindowDays));
  return isoDate(dt);
})();
const failures = [];

function checkPolicyEntry(advisory, kind) {
  const id = advisory?.advisory?.id;
  const pkg = advisory?.package?.name || "unknown-package";
  if (!id) {
    failures.push(`${kind} without advisory id for ${pkg}`);
    return;
  }
  const allowed = allow.get(id);
  if (!allowed) {
    failures.push(`unreviewed ${kind} ${id} (${pkg})`);
    return;
  }
  if (!allowed.review_by) {
    failures.push(`policy entry ${id} missing review_by date`);
    return;
  }
  if (allowed.review_by > maxReviewDate) {
    failures.push(
      `policy entry ${id} review_by ${allowed.review_by} exceeds ${maxReviewWindowDays} day window (${maxReviewDate})`
    );
  }
  if (allowed.review_by < today) {
    failures.push(`policy entry ${id} expired on ${allowed.review_by}`);
  }
}

const vulnerabilities = auditJson?.vulnerabilities?.list || [];
for (const vulnerability of vulnerabilities) {
  checkPolicyEntry(vulnerability, "vulnerability");
}

for (const warning of advisoryWarnings) {
  checkPolicyEntry(warning, "advisory");
}

const presentIds = new Set(
  [...vulnerabilities, ...advisoryWarnings].map((w) => w?.advisory?.id).filter(Boolean)
);
for (const [id] of allow.entries()) {
  if (!presentIds.has(id)) {
    failures.push(`stale allowlist entry ${id} is no longer present in audit output`);
  }
}

if (failures.length > 0) {
  console.error("audit-rust: policy check failed.");
  for (const line of failures) {
    console.error(`  - ${line}`);
  }
  process.exit(1);
}

console.log(
  `audit-rust: PASS (vulnerabilities=${vulnerabilities.length}, advisory_warnings=${advisoryWarnings.length}, date=${today}, max_review_window_days=${maxReviewWindowDays})`
);
