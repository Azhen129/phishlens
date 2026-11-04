// Keep transform-cache atomic writes inside the writable project workspace.
// Windows sandboxes can prohibit rename operations in the OS temporary folder.
import { mkdirSync } from "node:fs";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

const projectRoot = fileURLToPath(new URL("../", import.meta.url));
const testTemp = join(projectRoot, "work", "vitest-tmp");
mkdirSync(testTemp, { recursive: true });
const child = spawn(
  process.execPath,
  [
    join(projectRoot, "node_modules", "vitest", "vitest.mjs"),
    "run",
    ...process.argv.slice(2),
  ],
  {
    cwd: projectRoot,
    stdio: "inherit",
    env: { ...process.env, TMP: testTemp, TEMP: testTemp, TMPDIR: testTemp },
  },
);
child.on("error", (error) => {
  console.error(error.message);
  process.exitCode = 1;
});
child.on("exit", (code) => {
  process.exitCode = code ?? 1;
});
