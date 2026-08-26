/**
 * Loader for the optional OAuth/certificate peers (D4). A missing peer reaches
 * an embedder as Node's raw `ERR_MODULE_NOT_FOUND` otherwise — an untyped
 * `Error` no VaultError-shaped handler recognises.
 *
 * Lives beside DirectClient rather than inside it so the routing is observable:
 * a test can stand in for this module and see which specifier each lazy call
 * site asks for. Not re-exported from `index.ts` — package-internal.
 */

import { VaultError } from "@harpoc/shared";

/**
 * The message clause is load-bearing: an installed peer whose own dependency is
 * missing raises the same code, and reporting that as "install
 * @harpoc/oauth-proxy" would send the embedder after a package they already
 * have. It matches the *quoted* name, which is the one Node reports as missing
 * — a bare substring test also matches the unquoted importer path
 * ("… imported from /node_modules/@harpoc/oauth-proxy/dist/index.js"), i.e.
 * exactly the transitive case it is meant to exclude. A message shape that
 * does not quote falls through to the raw rethrow, the safe direction.
 */
function isModuleNotFound(err: unknown, specifier: string): boolean {
  const code = (err as NodeJS.ErrnoException | undefined)?.code;
  return (
    (code === "ERR_MODULE_NOT_FOUND" || code === "MODULE_NOT_FOUND") &&
    err instanceof Error &&
    err.message.includes(`'${specifier}'`)
  );
}

export async function importPeer<T>(specifier: string, load: () => Promise<T>): Promise<T> {
  try {
    return await load();
  } catch (err) {
    if (isModuleNotFound(err, specifier)) throw VaultError.missingDependency(specifier);
    throw err;
  }
}
