const KEY = "harpoc.theme";

export type ThemePreference = "light" | "dark" | null;

export function storedTheme(): ThemePreference {
  try {
    const value = sessionStorage.getItem(KEY);
    return value === "light" || value === "dark" ? value : null;
  } catch {
    return null;
  }
}

export function applyTheme(pref: ThemePreference): void {
  const root = document.documentElement;
  if (pref === null) root.removeAttribute("data-theme");
  else root.setAttribute("data-theme", pref);
}

export function setTheme(pref: ThemePreference): void {
  try {
    if (pref === null) sessionStorage.removeItem(KEY);
    else sessionStorage.setItem(KEY, pref);
  } catch {
    // Storage refusals (private mode) leave the choice session-local in memory.
  }
  applyTheme(pref);
}

export function cycleTheme(): ThemePreference {
  const order: ThemePreference[] = [null, "light", "dark"];
  const next = order[(order.indexOf(storedTheme()) + 1) % order.length] ?? null;
  setTheme(next);
  return next;
}
