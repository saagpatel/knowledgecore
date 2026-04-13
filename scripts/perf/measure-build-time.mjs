import { spawnSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";

const commandArgs = process.argv.slice(2);

let command = null;
let spawnArgs = null;
let useShell = false;

if (commandArgs.length > 0) {
  command = commandArgs.join(" ");
  spawnArgs = [command];
  useShell = true;
} else {
  const npmExecPath = process.env.npm_execpath;
  if (!npmExecPath) {
    console.error("npm_execpath is not set; run this script through pnpm, npm, or yarn.");
    process.exit(1);
  }
  command = "npm_execpath run build";
  spawnArgs = [process.execPath, npmExecPath, "run", "build"];
}

const start = Date.now();
const result = useShell
  ? spawnSync(command, {
      stdio: "inherit",
      shell: true,
    })
  : spawnSync(spawnArgs[0], spawnArgs.slice(1), {
      stdio: "inherit",
    });
const end = Date.now();

mkdirSync(".perf-results", { recursive: true });
writeFileSync(
  ".perf-results/build-time.json",
  JSON.stringify(
      {
        buildMs: end - start,
        capturedAt: new Date().toISOString(),
        command,
      },
    null,
    2,
  ),
);

if (result.status !== 0) {
  process.exit(result.status ?? 1);
}
