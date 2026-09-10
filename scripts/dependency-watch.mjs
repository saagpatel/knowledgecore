#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

function fail(message) {
  console.error(`dependency-watch: ${message}`);
  process.exit(1);
}

function parseArgs(argv) {
  return {
    noFail: argv.includes("--no-fail")
  };
}

function parseSemver(version) {
  const match = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+.*)?$/.exec(version);
  if (!match) {
    return null;
  }
  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
    prerelease: match[4] ? match[4].split(".") : []
  };
}

function compareIdentifier(a, b) {
  const aNumeric = /^\d+$/.test(a);
  const bNumeric = /^\d+$/.test(b);
  if (aNumeric && bNumeric) {
    return Number(a) - Number(b);
  }
  if (aNumeric && !bNumeric) {
    return -1;
  }
  if (!aNumeric && bNumeric) {
    return 1;
  }
  return a.localeCompare(b);
}

function compareSemver(a, b) {
  const left = parseSemver(a);
  const right = parseSemver(b);
  if (!left || !right) {
    return 0;
  }
  if (left.major !== right.major) {
    return left.major - right.major;
  }
  if (left.minor !== right.minor) {
    return left.minor - right.minor;
  }
  if (left.patch !== right.patch) {
    return left.patch - right.patch;
  }

  if (left.prerelease.length === 0 && right.prerelease.length > 0) {
    return 1;
  }
  if (left.prerelease.length > 0 && right.prerelease.length === 0) {
    return -1;
  }

  const length = Math.max(left.prerelease.length, right.prerelease.length);
  for (let i = 0; i < length; i += 1) {
    const l = left.prerelease[i];
    const r = right.prerelease[i];
    if (l === undefined) {
      return -1;
    }
    if (r === undefined) {
      return 1;
    }
    const diff = compareIdentifier(l, r);
    if (diff !== 0) {
      return diff;
    }
  }
  return 0;
}

function maxVersion(versions) {
  if (versions.length === 0) {
    return null;
  }
  return versions.reduce((current, candidate) => {
    if (compareSemver(candidate, current) > 0) {
      return candidate;
    }
    return current;
  });
}

async function fetchLatestCrateVersion(crateName) {
  const response = await fetch(`https://crates.io/api/v1/crates/${encodeURIComponent(crateName)}`, {
    headers: {
      "user-agent": "knowledgecore-dependency-watch/1.0"
    }
  });
  if (!response.ok) {
    throw new Error(`crates.io request failed (${response.status})`);
  }
  const payload = await response.json();
  const crate = payload?.crate;
  const latest = crate?.max_stable_version || crate?.max_version || crate?.newest_version;
  if (!latest) {
    throw new Error("latest version missing from crates.io response");
  }
  return latest;
}

function writeGithubSummary(reportRows, failures, advisoryOnly) {
  const summaryPath = process.env.GITHUB_STEP_SUMMARY;
  if (!summaryPath) {
    return;
  }

  const lines = [
    "## Dependency Watch",
    "",
    `- Mode: ${advisoryOnly ? "advisory" : "strict"}`,
    `- Timestamp (UTC): ${new Date().toISOString()}`,
    "",
    "| Crate | Group | Current | Latest | Outcome |",
    "|---|---|---|---|---|"
  ];

  for (const row of reportRows) {
    lines.push(
      `| ${row.name} | ${row.group} | ${row.currentVersion} | ${row.latestVersion} | ${row.outcome} |`
    );
  }

  if (failures.length > 0) {
    lines.push("", "### Failures");
    for (const failure of failures) {
      lines.push(`- ${failure}`);
    }
  }

  fs.appendFileSync(summaryPath, `${lines.join("\n")}\n`);
}

async function main() {
  const { noFail } = parseArgs(process.argv.slice(2));
  const scriptDir = path.dirname(fileURLToPath(import.meta.url));
  const repoRoot = path.resolve(scriptDir, "..");
  const watchPath = path.join(repoRoot, "security", "dependency-watch.json");

  if (!fs.existsSync(watchPath)) {
    fail(`missing config at ${watchPath}`);
  }

  const config = JSON.parse(fs.readFileSync(watchPath, "utf8"));
  const watched = Array.isArray(config.dependencies) ? config.dependencies : [];
  if (watched.length === 0) {
    fail("no dependencies configured in security/dependency-watch.json");
  }

  let metadata;
  try {
    metadata = JSON.parse(
      execFileSync("cargo", ["metadata", "--format-version", "1", "--locked"], {
        cwd: repoRoot,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
        maxBuffer: 128 * 1024 * 1024
      })
    );
  } catch (error) {
    fail(`failed to run cargo metadata --format-version 1 --locked (${error.message})`);
  }

  const versionsByName = new Map();
  for (const pkg of metadata.packages || []) {
    const source = pkg.source || "";
    if (source.length > 0 && !source.startsWith("registry+")) {
      continue;
    }
    if (!versionsByName.has(pkg.name)) {
      versionsByName.set(pkg.name, new Set());
    }
    versionsByName.get(pkg.name).add(pkg.version);
  }

  const reportRows = [];
  const failures = [];

  for (const dep of watched) {
    const name = dep.name;
    if (!name) {
      failures.push("dependency-watch.json contains an entry without a name");
      continue;
    }

    const versions = [...(versionsByName.get(name) || [])];
    const currentVersion = maxVersion(versions);
    if (!currentVersion) {
      failures.push(`crate '${name}' was not found in current Cargo graph`);
      reportRows.push({
        name,
        group: dep.group || "unknown",
        currentVersion: "not-found",
        latestVersion: "n/a",
        outcome: "missing"
      });
      continue;
    }

    let latestVersion = "unknown";
    let compare = 0;
    try {
      latestVersion = await fetchLatestCrateVersion(name);
      compare = compareSemver(latestVersion, currentVersion);
    } catch (error) {
      failures.push(`failed to fetch latest version for '${name}' (${error.message})`);
      reportRows.push({
        name,
        group: dep.group || "unknown",
        currentVersion,
        latestVersion: "fetch-error",
        outcome: "error"
      });
      continue;
    }

    const isOutdated = compare > 0;
    const shouldFail = Boolean(dep.fail_on_update) && isOutdated && !noFail;
    const outcome = isOutdated ? (shouldFail ? "outdated-fail" : "outdated-warn") : "up-to-date";

    if (shouldFail) {
      failures.push(
        `${name} is outdated (${currentVersion} -> ${latestVersion}); fail_on_update is enabled`
      );
    }

    reportRows.push({
      name,
      group: dep.group || "unknown",
      currentVersion,
      latestVersion,
      outcome
    });
  }

  console.log(`dependency-watch: mode=${noFail ? "advisory" : "strict"}`);
  for (const row of reportRows) {
    console.log(
      `  - ${row.name.padEnd(12)} group=${row.group.padEnd(10)} current=${row.currentVersion.padEnd(12)} latest=${row.latestVersion.padEnd(12)} outcome=${row.outcome}`
    );
  }

  writeGithubSummary(reportRows, failures, noFail);

  if (failures.length > 0) {
    if (noFail) {
      console.warn("dependency-watch: advisory warnings:");
      for (const failure of failures) {
        console.warn(`  - ${failure}`);
      }
      console.log("dependency-watch: completed with warnings (non-blocking)");
      return;
    }
    console.error("dependency-watch: strict check failed");
    for (const failure of failures) {
      console.error(`  - ${failure}`);
    }
    process.exit(1);
  }

  console.log("dependency-watch: PASS");
}

main().catch((error) => {
  fail(`unexpected error (${error.message})`);
});
