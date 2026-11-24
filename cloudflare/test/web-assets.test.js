import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

test("browser assets: JavaScript syntax and import graph", () => {
  const script = fileURLToPath(new URL("../../scripts/check-web-assets.mjs", import.meta.url));
  const result = spawnSync(process.execPath, [script], { encoding: "utf8" });
  assert.equal(
    result.status,
    0,
    `web-assets check failed:\n${result.stdout || ""}\n${result.stderr || ""}`,
  );
  assert.match(result.stdout, /PASS web-assets/);
});
