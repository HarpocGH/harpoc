import { existsSync, readdirSync, readFileSync } from "node:fs";
import { builtinModules } from "node:module";
import { resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { describeBuildOutput, getPkgRoot } from "@harpoc/test-utils";

const pkgRoot = getPkgRoot(import.meta.url);
const monorepoRoot = resolve(pkgRoot, "..", "..");
const sharedDistDir = resolve(monorepoRoot, "packages", "shared", "dist");
const sharedSrcDir = resolve(monorepoRoot, "packages", "shared", "src");

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
/** Dist libraries whose `exports["."]` is not `dist/index` — the entry's basename, and why. */
const LIBRARY_ENTRY: Record<string, { entry: string; reason: string }> = {
  "mcp-server": {
    entry: "lib",
    reason:
      "dist/index.js is the harpoc-mcp binary, whose static graph must not load the engine (B1)",
  },
};
const PACKAGES = WORKSPACE.filter((p) => !Object.hasOwn(NOT_A_DIST_LIBRARY, p));
/** The root manifest and every workspace package's, relative to the monorepo root. */
const MANIFESTS = ["package.json", ...WORKSPACE.map((p) => `packages/${p}/package.json`)];

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

/**
 * The indented lines under one top-level key of a YAML file, comments and blank
 * lines dropped — read as lines, the way ciTestEnvNames reads ci.yml; a key
 * that is absent (or written in flow style) reads as an empty block.
 */
function yamlBlock(yaml: string, key: string): string[] {
  const lines = yaml.split(/\r?\n/);
  const start = lines.indexOf(`${key}:`);
  if (start < 0) return [];
  const block: string[] = [];
  for (const l of lines.slice(start + 1)) {
    if (/^\s*(#.*)?$/.test(l)) continue;
    if (!/^\s/.test(l)) break;
    block.push(l);
  }
  return block;
}

/** The index just past the literal that opens at `from` and closes with `quote` (in a template, just past a `${` too), skipping escaped characters and a `/` inside a regular expression's `[…]`; an unclosed string or regular expression ends at its line's end. */
function literalEnd(source: string, from: number, quote: string): number {
  let inClass = false;
  for (let at = from + 1; at < source.length; at++) {
    const c = source.charAt(at);
    if (c === "\\") at++;
    else if (quote === "`" && c === "$" && source.charAt(at + 1) === "{") return at + 2;
    else if (quote === "/" && (c === "[" || c === "]")) inClass = c === "[";
    else if (c === quote && !inClass) return at + 1;
    else if (c === "\n" && quote !== "`") return at;
  }
  return source.length;
}

/** A TypeScript source without its comments (`uncommented`) and, in `code`, also without the text of its string, template and regular-expression literals — a template's `${…}` stays code, and a `/` opens a regular expression only after an operator other than a postfix `++` or `--`, an opening bracket, a brace, a comma, a semicolon or a keyword that is not a property's name, and is division after anything else. */
function stripSource(source: string): { code: string; uncommented: string } {
  const regexMayOpen =
    /(?:^|[(,=:[!&|?{};*%<>~^]|(?<!\+)\+|(?<!-)-|(?<![.$])\b(?:return|typeof|case|do|else|in|of|new|delete|void|throw|instanceof|yield|await))\s*$/;
  const templates: number[] = [];
  let code = "";
  let uncommented = "";
  let at = 0;
  while (at < source.length) {
    const c = source.charAt(at);
    const two = source.slice(at, at + 2);
    if (two === "//" || two === "/*") {
      const ends = source.indexOf(two === "//" ? "\n" : "*/", at + 2);
      at = ends < 0 ? source.length : two === "//" ? ends : ends + 2;
      code += " ";
      uncommented += " ";
    } else if (
      c === '"' ||
      c === "'" ||
      c === "`" ||
      (c === "}" && templates.at(-1) === 0) ||
      (c === "/" && regexMayOpen.test(code))
    ) {
      if (c === "}") templates.pop();
      const quote = c === "}" ? "`" : c;
      const end = literalEnd(source, at, quote);
      const interpolates = quote === "`" && source.slice(end - 2, end) === "${";
      if (interpolates) templates.push(0);
      code += quote === "`" ? `${c}${interpolates ? "${" : "`"}` : '""';
      uncommented += source.slice(at, end);
      at = end;
    } else {
      if (templates.length > 0 && (c === "{" || c === "}")) {
        templates[templates.length - 1] = (templates.at(-1) ?? 0) + (c === "{" ? 1 : -1);
      }
      code += c;
      uncommented += c;
      at++;
    }
  }
  return { code, uncommented };
}

const NODE_ONLY_GLOBALS = [
  "Buffer",
  "process",
  "__dirname",
  "__filename",
  "setImmediate",
  "global",
] as const;

const CREDENTIAL_NEEDLE_NAMES = [
  "ACCESS_TOKEN",
  "ACCESS_TOKEN_PREFIX",
  "ACCESS_TOKEN_VALUE",
  "AC_CLIENT_SECRET",
  "ALPHA_SECRET",
  "API_KEY_VALUE",
  "ARMOR_MARKER",
  "ARM_PASSWORD",
  "AUTH_PASSWORD",
  "B64",
  "BACKSLASH_CREDENTIAL",
  "BACKSLASH_CREDENTIAL_TAIL",
  "BACKSLASH_LITERAL",
  "BASIC",
  "BEARERISH",
  "BEARER_ACCESS_TOKEN",
  "BEARER_JWT_PREFIX",
  "BEARER_TOKEN",
  "BETA_SECRET",
  "BRIDGE_AMBIENT_TOKEN",
  "BRIDGE_FILE_TOKEN",
  "CAP_CREDENTIAL_TAIL",
  "CA_KEY_BODY",
  "CC_ACCESS_TOKEN",
  "CC_CLIENT_SECRET",
  "CLIENT_SECRET",
  "CREDENTIAL",
  "CREDENTIAL_PATTERN_TOKEN",
  "D2_BOUNDARY_CREDENTIAL",
  "D2_BOUNDARY_CREDENTIAL_TAIL",
  "DB_COUNTERPART_PASSWORD",
  "DB_PASSWORD",
  "DB_SECRET_FRAGMENT",
  "DB_USERNAME",
  "DESCENT_GATE_SECRET",
  "DESCENT_GATE_SECRET_TAIL",
  "DUPLICATE_SECRET_VALUE",
  "ECHOED_CREDENTIAL",
  "ENTERED_VALUE",
  "ESCAPE_LETTER_TOKEN",
  "ESCAPE_UNIT_TOKEN",
  "EXPIRED_SECRET_VALUE",
  "FLAT_PASS_SECRET",
  "FLOOR_USERNAME",
  "FORM_CREATE_VALUE",
  "FORM_POSTED_VALUE",
  "FORM_ROTATE_VALUE",
  "GIT_TOKEN",
  "GIT_USERNAME",
  "HEADER_ECHO_TOKEN",
  "HEAD_REQUEST_TOKEN",
  "HEX",
  "HIDDEN_VALUE",
  "IGNORED_PASSWORD",
  "IGNORED_SECRET",
  "JWT_PREFIX",
  "KEY_AUTHORIZATION",
  "KEY_B64",
  "KEY_HEX",
  "KEY_MARKER",
  "KEY_POSITION_CREDENTIAL",
  "KEY_POSITION_CREDENTIAL_TAIL",
  "LAUNCHER_PASSWORD",
  "LITERAL_TOKEN",
  "LOGIN_PASSWORD",
  "LOGON_PASSWORD",
  "LONGER_VALUE",
  "MCP_CC_ACCESS_TOKEN",
  "MCP_CC_CLIENT_SECRET",
  "MCP_USE_SECRET",
  "MINTED_TOKEN",
  "MULTIBYTE_NEEDLE",
  "MY_CLIENT_SECRET",
  "NEEDLE",
  "NON_ASCII_CREDENTIAL_PREFIX",
  "NON_ASCII_ESCAPE_FRAGMENT",
  "NO_USE_TOKEN",
  "OAUTH_CLIENT_SECRET",
  "OAUTH_TOKEN",
  "PASSWORD_HALF",
  "PASSWORD_NEEDLE",
  "PASSWORD_WITH_AT",
  "PASTED_TOKEN",
  "PEM_ARMOR",
  "PEM_KEY_BODY",
  "PHP_CREDENTIAL_PREFIX",
  "PHP_ESCAPED_CREDENTIAL",
  "PLAINTEXT",
  "PLAIN_CRED",
  "PLAIN_SECRET",
  "PLAIN_VALUE",
  "PRIVATE_KEY_ARMOR",
  "PROC_SECRET",
  "PROMPT_CLIENT_SECRET",
  "PROMPT_CREATE_VALUE",
  "PROMPT_ROTATE_VALUE",
  "PROTO_SIBLING_CREDENTIAL_TAIL",
  "PUSH_TOKEN",
  "QUERY_TOKEN",
  "QUOTE_CREDENTIAL_TAIL",
  "REFRESHED_ACCESS_TOKEN",
  "REFRESH_TOKEN",
  "REFRESH_TOKEN_VALUE",
  "REFUSED_LAUNCH_TOKEN_PART",
  "REFUSED_TOKEN",
  "REGISTRY_PASSWORD",
  "REGISTRY_USER",
  "REMOVED_FLAG_TOKEN",
  "REPEATED_TOKEN",
  "REVOKED_SECRET_VALUE",
  "ROTATED_SECRET",
  "SANITIZATION_SECRET_PREFIX",
  "SECOND_CREDENTIAL",
  "SECRET",
  "SECRET_TOKEN",
  "SECRET_VALUE",
  "SEEDED_ACCESS_TOKEN",
  "SEEDED_REFRESH_TOKEN",
  "SENTINEL",
  "SHORT_USERNAME",
  "STORED_PASSPHRASE",
  "SUPERSEDED_TOKEN",
  "TARGET_VALUE",
  "TEMP_PATH_CREDENTIAL",
  "TOKEN",
  "TOKENLESS_AMBIENT_TOKEN",
  "TOKEN_FILE_PREFIX",
  "TOKEN_FRAGMENT",
  "TYPED_PASSPHRASE",
  "TYPED_PASSWORD",
  "TYPED_PREFIX",
  "TYPED_VALUE",
  "UNICODE_ESCAPE_CREDENTIAL",
  "URL_CREDENTIAL",
  "URL_PASSWORD",
  "USER",
  "USERINFO_PASSWORD",
  "VALUE",
  "VALUE_BEFORE_LF",
  "WRONG_PASSPHRASE",
  "WRONG_PASSWORD_PREFIX",
] as const;
const EXPECT_ABSENT_MESSAGE =
  "use expectAbsent from @harpoc/test-utils: a failing not.toContain prints both operands";

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
        const base = LIBRARY_ENTRY[pkg]?.entry ?? "index";
        expect(entry.types).toBe(`./dist/${base}.d.ts`);
        expect(entry.import).toBe(`./dist/${base}.js`);
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
    const exempted = [...Object.keys(NOT_A_DIST_LIBRARY), ...Object.keys(LIBRARY_ENTRY)];
    expect(exempted.filter((p) => !WORKSPACE.includes(p))).toEqual([]);
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
  const manifests = MANIFESTS;

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
// keychain suites ran against the runner's login keychain. The two-UID suite's
// users (tranche B1) ride the same list.
describe("turbo env pass-through (D5, 2026-09-08; the series file 2026-09-09)", () => {
  it("the test task names the five variables ci.yml sets for it", () => {
    const raw = readFileSync(resolve(monorepoRoot, "turbo.json"), "utf-8");
    const turbo = JSON.parse(raw) as {
      tasks: Record<string, { env?: string[] }>;
    };
    expect(turbo.tasks["test"]?.env).toEqual([
      "HARPOC_REQUIRE_PLATFORM_TESTS",
      "HARPOC_TEST_KEYCHAIN",
      "HARPOC_SERIES_FILE",
      "HARPOC_TWO_UID_VAULT_USER",
      "HARPOC_TWO_UID_AGENT_USER",
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

describe("ci.yml's triggers (L13)", () => {
  it("ci.yml starts on a push to main, a pull request to main and a manual start, and on nothing else", () => {
    const ci = readFileSync(resolve(monorepoRoot, ".github", "workflows", "ci.yml"), "utf-8");
    expect(yamlBlock(ci, "on")).toEqual([
      "  push:",
      "    branches: [main]",
      "  pull_request:",
      "    branches: [main]",
      "  workflow_dispatch:",
    ]);
  });
});

describe("turbo's global hash names the root files every package's tasks read (T7)", () => {
  it("globalDependencies names tsconfig.base.json and eslint.config.js", () => {
    const turbo = JSON.parse(readFileSync(resolve(monorepoRoot, "turbo.json"), "utf-8")) as {
      globalDependencies?: string[];
    };
    expect(turbo.globalDependencies).toEqual(["tsconfig.base.json", "eslint.config.js"]);
  });
});

describe("the base lib is ES2022 without DOM (U-4, C-24)", () => {
  it("tsconfig.base.json's lib is ES2022 alone and only web-ui's tsconfig.json names a DOM lib", () => {
    const base = JSON.parse(readFileSync(resolve(monorepoRoot, "tsconfig.base.json"), "utf-8")) as {
      compilerOptions: { lib?: string[] };
    };
    expect(base.compilerOptions.lib).toEqual(["ES2022"]);
    const namingDom = WORKSPACE.flatMap((pkg) =>
      readdirSync(resolve(monorepoRoot, "packages", pkg))
        .filter((file) => /^tsconfig.*\.json$/.test(file))
        .map((file) => `packages/${pkg}/${file}`),
    ).filter((path) => {
      const config = JSON.parse(readFileSync(resolve(monorepoRoot, path), "utf-8")) as {
        compilerOptions?: { lib?: string[] };
      };
      return (config.compilerOptions?.lib ?? []).some((lib) => /^dom(\.|$)/i.test(lib));
    });
    expect(namingDom).toEqual(["packages/web-ui/tsconfig.json"]);
  });

  it("shared's product code names no Node-only global and imports no node: module (it builds with Node's types, and web-ui runs it in the browser)", () => {
    const files = readdirSync(sharedSrcDir, { recursive: true, encoding: "utf8" })
      .map((path) => path.split(sep).join("/"))
      .filter(
        (path) =>
          path.endsWith(".ts") &&
          !path.endsWith(".test.ts") &&
          !path.split("/").includes("__fixtures__"),
      )
      .sort();
    expect(files.length).toBeGreaterThan(0);
    const uses = files.flatMap((file) => {
      const { code, uncommented } = stripSource(readFileSync(resolve(sharedSrcDir, file), "utf8"));
      const found = [
        ...[...uncommented.matchAll(/(?<![\w$.])(?:from|import\s*\(?)\s*["'`](node:[^"'`]*)/g)].map(
          (match) => match[1] ?? "",
        ),
        ...(/(?<![\w$])require\s*\(/.test(code) ? ["require("] : []),
        ...NODE_ONLY_GLOBALS.filter((identifier) =>
          new RegExp(`(?<![\\w$])${identifier}(?![\\w$])`).test(code),
        ),
      ];
      return found.map((identifier) => `${file}: ${identifier}`);
    });
    expect(uses).toEqual([]);
  });

  it("eslint.config.js refuses the same names in shared's product code, require, node: imports, Node's builtin modules by their bare names, globalThis.process and globalThis.Buffer included (C-3)", async () => {
    type FlatConfig = { files?: unknown; ignores?: unknown; rules?: Record<string, unknown> };
    const { default: configs } = (await import(
      pathToFileURL(resolve(monorepoRoot, "eslint.config.js")).href
    )) as { default: FlatConfig[] };
    const blocks = configs.filter(
      (config) => JSON.stringify(config.files) === JSON.stringify(["packages/shared/src/**/*.ts"]),
    );
    expect(blocks).toHaveLength(1);
    const block = blocks[0] as FlatConfig;
    expect(block.ignores).toEqual([
      "packages/shared/src/**/*.test.ts",
      "packages/shared/src/**/__fixtures__/**",
    ]);
    expect(block.rules).toEqual({
      "no-restricted-globals": ["error", ...NODE_ONLY_GLOBALS, "require"],
      "no-restricted-imports": [
        "error",
        {
          paths: builtinModules.filter((name) => !name.startsWith("node:")),
          patterns: ["node:*"],
        },
      ],
      "no-restricted-properties": [
        "error",
        { object: "globalThis", property: "process" },
        { object: "globalThis", property: "Buffer" },
      ],
    });
  });

  it("eslint.config.js refuses .not.toContain(<name>) in test files for every constant name the redaction sweep checks for absence (C-8)", async () => {
    type FlatConfig = { files?: unknown; ignores?: unknown; rules?: Record<string, unknown> };
    const { default: configs } = (await import(
      pathToFileURL(resolve(monorepoRoot, "eslint.config.js")).href
    )) as { default: FlatConfig[] };
    const files = ["packages/*/src/**/*.test.ts", "packages/*/src/**/*.test.tsx"];
    const blocks = configs.filter(
      (config) => JSON.stringify(config.files) === JSON.stringify(files),
    );
    expect(blocks).toHaveLength(1);
    expect(blocks[0]).toEqual({
      files,
      rules: {
        "no-restricted-syntax": [
          "error",
          {
            selector: `CallExpression[callee.property.name="toContain"][callee.object.type="MemberExpression"][callee.object.property.name="not"][arguments.0.type="Identifier"][arguments.0.name=/^(?:${CREDENTIAL_NEEDLE_NAMES.join("|")})$/]`,
            message: EXPECT_ABSENT_MESSAGE,
          },
        ],
      },
    });
  });

  it("the root config reports .not.toContain on a listed name in a test file and passes a literal needle and expectAbsent (C-8)", async () => {
    const { ESLint } = await import("eslint");
    const linter = new ESLint({
      cwd: monorepoRoot,
      overrideConfigFile: resolve(monorepoRoot, "eslint.config.js"),
    });
    const filePath = resolve(monorepoRoot, "packages", "core", "src", "example.test.ts");
    const lint = async (code: string) =>
      (await linter.lintText(code, { filePath }))
        .flatMap((result) => result.messages)
        .map(({ ruleId, severity, message }) => ({ ruleId, severity, message }));
    expect(await lint("expect(text).not.toContain(SECRET);\n")).toEqual([
      { ruleId: "no-restricted-syntax", severity: 2, message: EXPECT_ABSENT_MESSAGE },
    ]);
    expect(await lint('expect(text).not.toContain("x");\n')).toEqual([]);
    expect(await lint("expectAbsent(text, SECRET);\n")).toEqual([]);
  });
});

const OUT_OF_PACKAGE_INPUTS = [
  "$TURBO_ROOT$/.github/workflows/*.yml",
  "$TURBO_ROOT$/deploy/**",
  "$TURBO_ROOT$/package.json",
  "$TURBO_ROOT$/pnpm-workspace.yaml",
  "$TURBO_ROOT$/.prettierignore",
  "$TURBO_ROOT$/packages/*/package.json",
  "$TURBO_ROOT$/packages/*/src/**/*.ts",
  "$TURBO_ROOT$/packages/*/src/**/*.tsx",
  "!$TURBO_ROOT$/**/NUL",
];

describe("integration's test task names the files it reads outside its package (W10)", () => {
  type PackageTurbo = {
    extends?: string[];
    tasks: Record<string, { inputs?: string[]; env?: string[]; dependsOn?: string[] }>;
  };
  let config: PackageTurbo;

  beforeAll(() => {
    config = JSON.parse(readFileSync(resolve(pkgRoot, "turbo.json"), "utf-8")) as PackageTurbo;
  });

  it("extends the root configuration and keeps its package's own files in the hash", () => {
    expect(config.extends).toEqual(["//"]);
    expect(config.tasks["test"]?.inputs).toContain("$TURBO_DEFAULT$");
  });

  it.each(OUT_OF_PACKAGE_INPUTS)("the test inputs name %s", (glob) => {
    expect(config.tasks["test"]?.inputs).toContain(glob);
  });

  it("leaves env and dependsOn to the root configuration", () => {
    expect(config.tasks["test"]?.env).toBeUndefined();
    expect(config.tasks["test"]?.dependsOn).toBeUndefined();
  });
});

describe("the root test script and the lockfile's formatting (DR, 2026-10-27)", () => {
  it("pnpm test runs turbo with --continue=dependencies-successful, so a red package never cancels the others", () => {
    const root = JSON.parse(readFileSync(resolve(monorepoRoot, "package.json"), "utf-8")) as {
      scripts: Record<string, string>;
    };
    expect(root.scripts["test"]).toBe("turbo run test --continue=dependencies-successful");
  });

  it("pnpm-lock.yaml is outside prettier's scope", () => {
    const ignored = readFileSync(resolve(monorepoRoot, ".prettierignore"), "utf-8").split(/\r?\n/);
    expect(ignored).toContain("pnpm-lock.yaml");
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

// I5 (test-review-2026-10-09): pnpm runs a dependency's install script only
// where the workspace allows it — onlyBuiltDependencies under pnpm 10 (the
// pinned packageManager), allowBuilds under pnpm 11 — and since DEP-9
// (2026-10-07) both allow argon2 alone: better-sqlite3 13 loads its prebuilt
// binary with its script refused (thesis 05:26 and its dated correction).
describe("install-time build scripts (I5)", () => {
  const workspaceYaml = readFileSync(resolve(monorepoRoot, "pnpm-workspace.yaml"), "utf-8");

  it("onlyBuiltDependencies names argon2 alone", () => {
    const names = yamlBlock(workspaceYaml, "onlyBuiltDependencies").map((l) => {
      const entry = /^ {2}- ([^\s#]+)\s*$/.exec(l);
      expect(entry, `onlyBuiltDependencies line ${JSON.stringify(l)}`).not.toBeNull();
      return entry?.[1];
    });
    expect(names).toEqual(["argon2"]);
  });

  it("allowBuilds allows argon2 alone and refuses better-sqlite3", () => {
    const verdicts = new Map<string, boolean>();
    for (const l of yamlBlock(workspaceYaml, "allowBuilds")) {
      const verdict = /^ {2}([^\s:#]+): (true|false)\s*$/.exec(l);
      expect(verdict, `allowBuilds line ${JSON.stringify(l)}`).not.toBeNull();
      verdicts.set(verdict?.[1] as string, verdict?.[2] === "true");
    }
    expect([...verdicts].filter(([, allowed]) => allowed).map(([name]) => name)).toEqual([
      "argon2",
    ]);
    expect(verdicts.get("better-sqlite3")).toBe(false);
  });
});

describe("yamlBlock reads one top-level key's lines", () => {
  it.each([
    ["stops at the next top-level key", ["a:", "  - x", "b:", "  - y"], "a", ["  - x"]],
    [
      "skips comments and blank lines inside the block",
      ["a:", "  # note", "", "  x: true"],
      "a",
      ["  x: true"],
    ],
    ["an absent key reads as an empty block", ["a:", "  - x"], "b", []],
    ["control: a flow-style value is not a block", ["a: [x]", "b:", "  - y"], "a", []],
  ])("%s", (_label, lines, key, expected) => {
    expect(yamlBlock(lines.join("\n"), key)).toEqual(expected);
  });
});

// M-T2a-10 (test-review-2026-10-09): thesis 04:54 — Argon2id through the
// argon2 binding is the only third-party code performing cryptographic
// operations, every other primitive node:crypto. The denylist names the
// crypto-implementing packages a manifest could pull in instead (fixed at
// U6's opening); argon2 is the one allowed, declared by core alone. The claim
// is the vault process's: ssh2, core's test-only devDependency (the SSH server
// of ssh-live-auth.test.ts), is not on the list.
const CRYPTO_DENYLIST = [
  "node-forge",
  "tweetnacl",
  "sodium-native",
  "libsodium-wrappers",
  "bcrypt",
  "bcryptjs",
  "crypto-js",
  "elliptic",
  "jsrsasign",
  "node-rsa",
  "openpgp",
] as const;

/** Every `<manifest> <block>` declaring `name`, over the root and every package manifest. */
function declarationsOf(name: string): string[] {
  return MANIFESTS.flatMap((path) => {
    const manifest = JSON.parse(readFileSync(resolve(monorepoRoot, path), "utf-8")) as Record<
      string,
      Record<string, unknown> | undefined
    >;
    return DEPENDENCY_BLOCKS.filter((block) => Object.hasOwn(manifest[block] ?? {}, name)).map(
      (block) => `${path} ${block}`,
    );
  });
}

describe("no third-party crypto library beside argon2 (M-T2a-10)", () => {
  it.each(CRYPTO_DENYLIST)("no manifest declares %s", (name) => {
    expect(declarationsOf(name)).toEqual([]);
  });

  it("argon2 is declared once, in core's dependencies", () => {
    expect(declarationsOf("argon2")).toEqual(["packages/core/package.json dependencies"]);
  });
});
