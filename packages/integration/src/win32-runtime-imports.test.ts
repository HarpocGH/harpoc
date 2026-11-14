import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { getPkgRoot } from "@harpoc/test-utils";

const repoRoot = resolve(getPkgRoot(import.meta.url), "..", "..");

const VC_RUNTIME = ["VCRUNTIME140.dll", "VCRUNTIME140_1.dll", "MSVCP140.dll"];

/** The DLL names a PE image imports, its delay-load table included, read from the file's import and delay-import directories. */
function peImports(path: string): string[] {
  const image = readFileSync(path);
  const pe = image.readUInt32LE(0x3c);
  if (image.toString("latin1", pe, pe + 4) !== "PE\0\0") throw new Error(`not a PE image: ${path}`);
  const sectionCount = image.readUInt16LE(pe + 6);
  const optionalSize = image.readUInt16LE(pe + 20);
  const optional = pe + 24;
  const directories = optional + (image.readUInt16LE(optional) === 0x20b ? 112 : 96);
  const sections = Array.from({ length: sectionCount }, (_, i) => {
    const at = optional + optionalSize + i * 40;
    return {
      va: image.readUInt32LE(at + 12),
      size: Math.max(image.readUInt32LE(at + 8), image.readUInt32LE(at + 16)),
      raw: image.readUInt32LE(at + 20),
    };
  });
  const offset = (rva: number): number => {
    const section = sections.find((s) => rva >= s.va && rva < s.va + s.size);
    if (section === undefined) throw new Error(`an RVA outside every section: ${path}`);
    return rva - section.va + section.raw;
  };
  const name = (rva: number): string => {
    const at = offset(rva);
    return image.toString("latin1", at, image.indexOf(0, at));
  };
  const names: string[] = [];
  const importRva = image.readUInt32LE(directories + 8);
  if (importRva !== 0) {
    for (let at = offset(importRva); image.readUInt32LE(at + 12) !== 0; at += 20) {
      names.push(name(image.readUInt32LE(at + 12)));
    }
  }
  const delayRva = image.readUInt32LE(directories + 13 * 8);
  if (delayRva !== 0) {
    for (let at = offset(delayRva); image.readUInt32LE(at + 4) !== 0; at += 32) {
      names.push(name(image.readUInt32LE(at + 4)));
    }
  }
  return names;
}

/** The directory of the package `name` as Node resolves it from the manifest at `from`. */
function packageDir(from: string, name: string): string {
  return dirname(createRequire(from).resolve(`${name}/package.json`));
}

/** The workspace's win32-x64 native binaries, each resolved along the dependency chain that installs it. */
function nativeBinaries(): Record<string, string> {
  const rootManifest = join(repoRoot, "package.json");
  const coreManifest = join(repoRoot, "packages", "core", "package.json");
  const turbo = packageDir(rootManifest, "turbo");
  const vite = packageDir(join(packageDir(rootManifest, "vitest"), "package.json"), "vite");
  const esbuild = packageDir(join(vite, "package.json"), "esbuild");
  const rollup = packageDir(join(vite, "package.json"), "rollup");
  const argon2 = packageDir(coreManifest, "argon2");
  const nodeGypBuild = createRequire(join(argon2, "package.json"))("node-gyp-build") as {
    path: (dir: string) => string;
  };
  return {
    "turbo.exe": join(
      packageDir(join(turbo, "package.json"), "@turbo/windows-64"),
      "bin",
      "turbo.exe",
    ),
    "esbuild.exe": join(
      packageDir(join(esbuild, "package.json"), "@esbuild/win32-x64"),
      "esbuild.exe",
    ),
    "rollup.win32-x64-msvc.node": join(
      packageDir(join(rollup, "package.json"), "@rollup/rollup-win32-x64-msvc"),
      "rollup.win32-x64-msvc.node",
    ),
    "better-sqlite3 prebuilds/win32-x64.node": join(
      packageDir(coreManifest, "better-sqlite3"),
      "prebuilds",
      "win32-x64.node",
    ),
    "argon2's win32-x64 prebuild": nodeGypBuild.path(argon2),
  };
}

/** The members of VC_RUNTIME among `names`, compared without case. */
function vcRuntimeAmong(names: string[]): string[] {
  const upper = new Set(names.map((n) => n.toUpperCase()));
  return VC_RUNTIME.filter((dll) => upper.has(dll.toUpperCase()));
}

describe.runIf(process.platform === "win32" && process.arch === "x64")(
  "the Visual C++ runtime in the import tables of the workspace's native binaries (win32-x64 only: the binaries read are the win32-x64 builds the workspace installs there)",
  () => {
    it("turbo.exe imports VCRUNTIME140.dll (the build's prerequisite on a bare Windows host)", () => {
      const names = peImports(nativeBinaries()["turbo.exe"] ?? "");
      expect(names.some((n) => n.toUpperCase() === "KERNEL32.DLL")).toBe(true);
      expect(vcRuntimeAmong(names)).toContain("VCRUNTIME140.dll");
    });

    it.each([
      "esbuild.exe",
      "rollup.win32-x64-msvc.node",
      "better-sqlite3 prebuilds/win32-x64.node",
      "argon2's win32-x64 prebuild",
    ])(
      "%s imports none of VCRUNTIME140.dll, VCRUNTIME140_1.dll, MSVCP140.dll, its delay-load table included",
      (binary) => {
        const names = peImports(nativeBinaries()[binary] ?? "");
        expect(names.some((n) => n.toUpperCase() === "KERNEL32.DLL")).toBe(true);
        expect(vcRuntimeAmong(names)).toEqual([]);
      },
    );
  },
);
