#!/usr/bin/env node
export {
  resolveVaultDir,
  createEngine,
  loadUnlockedEngine,
  resolveSecretId,
} from "./utils/vault-loader.js";
import { buildProgram } from "./program.js";

buildProgram().parse();
