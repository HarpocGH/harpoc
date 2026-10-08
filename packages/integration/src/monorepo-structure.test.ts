import { existsSync, readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import { describeBuildOutput, getPkgRoot } from "@harpoc/test-utils";

const pkgRoot = getPkgRoot(import.meta.url);
const monorepoRoot = resolve(pkgRoot, "..", "..");
const sharedDistDir = resolve(monorepoRoot, "packages", "shared", "dist");

const WORKSPACE = readdirSync(resolve(monorepoRoot, "packages"), { withFileTypes: true })
  .filter(
    (e) => e.isDirectory() && existsSync(resolve(monorepoRoot, "packages", e.name, "package.json")),
  )
  .map((e) => e.name)
  .sort();
/** Workspace packages that do not ship a built `dist` library entry, and why. */
const NOT_A_DIST_LIBRARY: Record<string, string> = {
  benchmarks: "the benchmark scripts, no entry",
  e2e: "the thesis harness, run by test:e2e",
  integration: "tests only",
  "test-utils": "source-only — exports ./src/index.ts",
  "web-ui": "a vite SPA served by rest-api — exports only ./package.json",
};
const PACKAGES = WORKSPACE.filter((p) => !Object.hasOwn(NOT_A_DIST_LIBRARY, p));

function ciTestEnvNames(yaml: string): string[] {
  const lines = yaml.split(/\r?\n/);
  const names = new Set<string>();
  let step: string[] = [];
  const flush = (): void => {
    if (step.some((l) => !/^\s*#/.test(l) && /\bpnpm test\b/.test(l))) {
      let envIndent = -1;
      for (const l of step) {
        const env = /^(\s*)env:\s*$/.exec(l);
        if (env) {
          envIndent = (env[1] ?? "").length;
          continue;
        }
        if (envIndent < 0 || /^\s*#/.test(l)) continue;
        const key = /^(\s*)([A-Z][A-Z0-9_]*):/.exec(l);
        if (key && (key[1] ?? "").length > envIndent) names.add(key[2] as string);
        else envIndent = -1;
      }
    }
    step = [];
  };
  for (const l of lines) {
    if (/^\s+- (name|run|uses):/.test(l)) flush();
    step.push(l);
  }
  flush();
  for (const l of lines) {
    const exported = /echo\s+"?([A-Z][A-Z0-9_]*)=.*>>\s*"?\$\{?GITHUB_ENV\}?"?/.exec(l);
    if (exported) names.add(exported[1] as string);
  }
  return [...names].sort();
}

describe("shared", () => {
  describeBuildOutput(sharedDistDir);
});

describe("monorepo structure", () => {
  for (const pkg of PACKAGES) {
    describe(pkg, () => {
      let pkgJson: Record<string, unknown>;

      beforeAll(() => {
        const raw = readFileSync(resolve(monorepoRoot, "packages", pkg, "package.json"), "utf-8");
        pkgJson = JSON.parse(raw) as Record<string, unknown>;
      });

      it('has "type": "module"', () => {
        expect(pkgJson.type).toBe("module");
      });

      it("has correct exports field", () => {
        expect(pkgJson.exports).toBeDefined();
        const exports = pkgJson.exports as Record<string, Record<string, string>>;
        expect(exports["."]).toBeDefined();
        const entry = exports["."] as Record<string, string>;
        expect(entry.types).toBe("./dist/index.d.ts");
        expect(entry.import).toBe("./dist/index.js");
      });

      it('has "build" script', () => {
        expect(pkgJson.scripts).toBeDefined();
        const scripts = pkgJson.scripts as Record<string, string>;
        expect(scripts.build).toBeDefined();
      });

      it('has "test" script', () => {
        expect(pkgJson.scripts).toBeDefined();
        const scripts = pkgJson.scripts as Record<string, string>;
        expect(scripts.test).toBeDefined();
      });
    });
  }

  it("every exemption names a workspace package", () => {
    expect(Object.keys(NOT_A_DIST_LIBRARY).filter((p) => !WORKSPACE.includes(p))).toEqual([]);
  });

  it.each(Object.keys(NOT_A_DIST_LIBRARY))('%s has "type": "module"', (pkg) => {
    const raw = readFileSync(resolve(monorepoRoot, "packages", pkg, "package.json"), "utf-8");
    expect((JSON.parse(raw) as Record<string, unknown>).type).toBe("module");
  });
});

describe("bin entries", () => {
  it('cli declares "harpoc" bin', () => {
    const raw = readFileSync(resolve(monorepoRoot, "packages", "cli", "package.json"), "utf-8");
    const pkgJson = JSON.parse(raw) as Record<string, unknown>;
    expect(pkgJson.bin).toBeDefined();
    const bin = pkgJson.bin as Record<string, string>;
    expect(bin.harpoc).toBe("./dist/index.js");
  });

  it('mcp-server declares "harpoc-mcp" bin', () => {
    const raw = readFileSync(
      resolve(monorepoRoot, "packages", "mcp-server", "package.json"),
      "utf-8",
    );
    const pkgJson = JSON.parse(raw) as Record<string, unknown>;
    expect(pkgJson.bin).toBeDefined();
    const bin = pkgJson.bin as Record<string, string>;
    expect(bin["harpoc-mcp"]).toBe("./dist/index.js");
  });
});

const DEPENDENCY_BLOCKS = [
  "dependencies",
  "devDependencies",
  "peerDependencies",
  "peerDependenciesMeta",
  "optionalDependencies",
] as const;

describe("manifest dependency blocks are sorted (TU-2, 2026-09-29)", () => {
  const manifests = [
    "package.json",
    ...readdirSync(resolve(monorepoRoot, "packages"), { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => `packages/${entry.name}/package.json`)
      .filter((path) => existsSync(resolve(monorepoRoot, path))),
  ];

  it("finds the root manifest and every package's", () => {
    expect(manifests.length).toBeGreaterThanOrEqual(14);
  });

  it.each(manifests)("%s lists every dependency block in code-unit order", (path) => {
    const manifest = JSON.parse(readFileSync(resolve(monorepoRoot, path), "utf-8")) as Record<
      string,
      Record<string, unknown> | undefined
    >;
    for (const block of DEPENDENCY_BLOCKS) {
      const names = Object.keys(manifest[block] ?? {});
      expect(names, `${path} ${block}`).toEqual([...names].sort());
    }
  });
});

// RED before turbo.json named them: turbo 2 runs tasks in strict env mode, so
// the variables ci.yml sets for the test step — the required-tier gate (review
// T3, 2026-07-16) and the provisioned macOS keychain, two at the 2026-09-08 RED
// (D5), the series file the Windows legs upload joining them 2026-09-09 — never
// reached a vitest worker under `pnpm test`; the gate was inert and the
// keychain suites ran against the runner's login keychain.
describe("turbo env pass-through (D5, 2026-09-08; the series file 2026-09-09)", () => {
  it("the test task names the three variables ci.yml sets for it", () => {
    const raw = readFileSync(resolve(monorepoRoot, "turbo.json"), "utf-8");
    const turbo = JSON.parse(raw) as {
      tasks: Record<string, { env?: string[] }>;
    };
    expect(turbo.tasks["test"]?.env).toEqual([
      "HARPOC_REQUIRE_PLATFORM_TESTS",
      "HARPOC_TEST_KEYCHAIN",
      "HARPOC_SERIES_FILE",
    ]);
  });

  it("the test task's env list is exactly what ci.yml exports to its test steps", () => {
    const turbo = JSON.parse(readFileSync(resolve(monorepoRoot, "turbo.json"), "utf-8")) as {
      tasks: Record<string, { env?: string[] }>;
    };
    const ci = readFileSync(resolve(monorepoRoot, ".github", "workflows", "ci.yml"), "utf-8");
    const exported = ciTestEnvNames(ci);
    expect(exported.length).toBeGreaterThanOrEqual(3);
    expect([...(turbo.tasks["test"]?.env ?? [])].sort()).toEqual(exported);
  });
});

describe("ciTestEnvNames reads a test step's own env and every $GITHUB_ENV export form", () => {
  it.each([
    [
      "a `run: |` test step's env",
      [
        "      - name: Test",
        "        env:",
        "          HARPOC_A: x",
        "        run: |",
        "          pnpm test",
      ],
      ["HARPOC_A"],
    ],
    [
      "an unquoted `>> $GITHUB_ENV` export",
      ['          echo "HARPOC_B=1" >> $GITHUB_ENV'],
      ["HARPOC_B"],
    ],
    ["an unquoted assignment", ['          echo HARPOC_C=1 >> "$GITHUB_ENV"'], ["HARPOC_C"]],
    [
      "control: a non-test step's env is not collected",
      ["      - name: Build", "        env:", "          HARPOC_D: x", "        run: pnpm build"],
      [],
    ],
    [
      "a braced ${GITHUB_ENV} export",
      ['          echo "HARPOC_E=1" >> "${GITHUB_ENV}"'],
      ["HARPOC_E"],
    ],
    [
      "control: a commented-out pnpm test does not make a test step",
      [
        "      - name: Build",
        "        env:",
        "          HARPOC_F: x",
        "        # pnpm test",
        "        run: pnpm build",
      ],
      [],
    ],
  ])("%s", (_label, lines, expected) => {
    expect(ciTestEnvNames(lines.join("\n"))).toEqual(expected);
  });
});
