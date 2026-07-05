/**
 * Build a clean child environment: the injected credential, a controlled PATH
 * and the explicitly allowlisted pass-through variables — nothing inherited
 * beyond that (thesis §4.5.3 layer 3). The credential is written last so an
 * allowlist entry cannot shadow it.
 */
export function buildCleanEnv(
  envVar: string,
  value: string,
  envAllowlist: string[],
): Record<string, string> {
  const env: Record<string, string> = {};
  const path = process.env.PATH ?? process.env.Path;
  if (path) env.PATH = path;
  for (const name of envAllowlist) {
    const v = process.env[name];
    if (v !== undefined) env[name] = v;
  }
  env[envVar] = value;
  return env;
}
