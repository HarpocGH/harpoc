import { createRequire } from "node:module";
import { Worker } from "node:worker_threads";
import { VaultError } from "@harpoc/shared";

export const VAULT_COPY_TIMEOUT_MS = 600_000;

export const VAULT_COPY_WORKER_SOURCE = `"use strict";
const { lstatSync } = require("node:fs");
const { parentPort, workerData } = require("node:worker_threads");
const { driver, dbPath, tmpPath, slotKeys } = workerData;
let step = "copy";
let db = null;
try {
  const Database = require(driver);
  db = new Database(dbPath, { readonly: true, fileMustExist: true });
  db.pragma("busy_timeout = 5000");
  db.pragma("synchronous = FULL");
  db.pragma("temp_store = MEMORY");
  const target = lstatSync(tmpPath);
  if (!target.isFile() || target.size !== 0) throw new Error(step);
  db.prepare("VACUUM INTO ?").run(tmpPath);
  db.close();
  step = "strip";
  db = new Database(tmpPath, { fileMustExist: true });
  if (db.pragma("journal_mode = MEMORY", { simple: true }) !== "memory") throw new Error(step);
  db.pragma("secure_delete = ON");
  db.pragma("temp_store = MEMORY");
  db.pragma("busy_timeout = 5000");
  const remove = db.prepare("DELETE FROM vault_meta WHERE key = ?");
  db.transaction(() => {
    for (const key of slotKeys) remove.run(key);
  })();
  step = "check";
  if (db.pragma("integrity_check", { simple: true }) !== "ok") throw new Error(step);
  db.close();
  step = "ok";
} catch {
  try {
    if (db !== null && db.open) db.close();
  } catch {}
}
parentPort.postMessage(step);
`;

const NOT_FINISHED = "backup did not finish";

function failureOf(answer: unknown): string | null {
  switch (answer) {
    case "ok":
      return null;
    case "copy":
      return "backup copy failed";
    case "strip":
      return "backup strip failed";
    case "check":
      return "backup check failed";
    default:
      return NOT_FINISHED;
  }
}

export function takeVaultCopy(
  request: { dbPath: string; tmpPath: string; slotKeys: readonly string[] },
  options: { timeoutMs?: number; signal?: AbortSignal } = {},
): Promise<void> {
  const { timeoutMs = VAULT_COPY_TIMEOUT_MS, signal } = options;
  return new Promise<void>((resolve, reject) => {
    if (signal?.aborted === true) {
      reject(VaultError.databaseError(NOT_FINISHED));
      return;
    }
    let worker: Worker;
    try {
      worker = new Worker(VAULT_COPY_WORKER_SOURCE, {
        eval: true,
        execArgv: [],
        workerData: {
          driver: createRequire(import.meta.url).resolve("better-sqlite3"),
          dbPath: request.dbPath,
          tmpPath: request.tmpPath,
          slotKeys: [...request.slotKeys],
        },
      });
    } catch {
      reject(VaultError.databaseError(NOT_FINISHED));
      return;
    }
    let settled = false;
    const end = (failure: string | null): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener("abort", abandon);
      void worker.terminate().then(() => {
        if (failure === null) resolve();
        else reject(VaultError.databaseError(failure));
      });
    };
    const abandon = (): void => end(NOT_FINISHED);
    const timer = setTimeout(abandon, timeoutMs);
    signal?.addEventListener("abort", abandon, { once: true });
    worker.on("message", (answer: unknown) => end(failureOf(answer)));
    worker.on("error", abandon);
    worker.on("exit", abandon);
  });
}
