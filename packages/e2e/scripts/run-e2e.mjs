// Runs the e2e suite with the fixture CA trusted process-wide.
//
// NODE_EXTRA_CA_CERTS is read ONCE per process, when the default root store is
// first touched — setting it from inside a vitest worker is too late and works
// only by accident. Setting it here, before vitest starts, means every
// descendant inherits it: the vitest workers that drive the http context
// against `echo-https`, and the CLI / stdio-MCP children the surface drivers
// spawn, which run their own vault process and their own TLS client.
//
// Dist-free on purpose (the generate-fixtures.mjs precedent): provisioning must
// work before anything in the workspace is built.
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

const caPath = fileURLToPath(new URL("../fixtures/pki/out/ca.crt", import.meta.url));

if (!existsSync(caPath)) {
  console.error(
    `run-e2e: fixture CA missing at ${caPath}\n` +
      "  run: pnpm --filter @harpoc/e2e fleet:up   (or: pnpm --filter @harpoc/e2e pki)",
  );
  process.exit(1);
}

// An operator-supplied bundle wins: overwriting it would silently drop whatever
// trust their environment already needed.
const env = { ...process.env };
if (!env.NODE_EXTRA_CA_CERTS) env.NODE_EXTRA_CA_CERTS = caPath;

// vitest's own ESM entry, run by this Node — never `npx` behind `shell: true`,
// which on Windows would hand the operator's filter arguments to cmd.exe for a
// second round of parsing. Arguments stay data, as everywhere else in the repo.
const vitestEntry = fileURLToPath(new URL("../node_modules/vitest/vitest.mjs", import.meta.url));
const vitestBin = existsSync(vitestEntry)
  ? vitestEntry
  : fileURLToPath(new URL("../../../node_modules/vitest/vitest.mjs", import.meta.url));

if (!existsSync(vitestBin)) {
  console.error("run-e2e: vitest is not installed\n  run: npx pnpm install");
  process.exit(1);
}

const result = spawnSync(process.execPath, [vitestBin, "run", ...process.argv.slice(2)], {
  stdio: "inherit",
  env,
  shell: false,
});

process.exit(result.status ?? 1);
