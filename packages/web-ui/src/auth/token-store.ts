const KEY = "harpoc.ui.token";

/**
 * Adopt the launch token from the URL fragment (`/ui#token=<jwt>`). The
 * fragment never reaches server logs; scrub it from the address bar
 * immediately so it survives neither history nor copy-paste. Session storage
 * only — the token dies with the tab (spec § 3.3); the persistent web-storage
 * area is deliberately never written, and `posture.test.ts` pins that.
 */
export function adoptLaunchToken(): void {
  const match = /^#token=(?<jwt>.+)$/.exec(window.location.hash);
  const jwt = match?.groups?.jwt;
  if (jwt === undefined) return;
  window.sessionStorage.setItem(KEY, jwt);
  history.replaceState(null, "", window.location.pathname + window.location.search);
}

export function getToken(): string | null {
  return window.sessionStorage.getItem(KEY);
}

export function setToken(jwt: string): void {
  window.sessionStorage.setItem(KEY, jwt);
}

export function clearToken(): void {
  window.sessionStorage.removeItem(KEY);
}
