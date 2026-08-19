import { useEffect, useState } from "preact/hooks";

/**
 * Hash routing, not history routing: the UI is served from one static entry
 * point (`/ui/index.html`) and the API owns every other path, so a deep link
 * must survive a reload without a server-side rewrite rule.
 */
export function currentRoute(): string {
  const hash = window.location.hash;
  return hash.startsWith("#/") ? hash.slice(1) : "/";
}

export function navigate(route: string): void {
  window.location.hash = `#${route}`;
}

export function useHashRoute(): string {
  const [route, setRoute] = useState(currentRoute());
  useEffect(() => {
    const onChange = (): void => setRoute(currentRoute());
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  return route;
}
