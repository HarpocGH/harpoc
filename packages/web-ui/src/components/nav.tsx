import { useState } from "preact/hooks";
import { cycleTheme, storedTheme } from "../theme";

const LINKS = [
  ["/", "Dashboard"],
  ["/secrets", "Secrets"],
  ["/audit", "Audit"],
  ["/agents", "Agents"],
  ["/permissions", "Permissions"],
  ["/tokens", "Tokens"],
] as const;

export function Nav({ route }: { route: string }) {
  const [theme, setThemeState] = useState(storedTheme());
  return (
    <nav class="rail">
      {LINKS.map(([target, label]) => (
        <a
          key={target}
          href={`#${target}`}
          data-active={target === "/" ? route === "/" : route.startsWith(target)}
        >
          {label}
        </a>
      ))}
      <button class="theme-toggle" type="button" onClick={() => setThemeState(cycleTheme())}>
        theme: {theme ?? "system"}
      </button>
    </nav>
  );
}
