const LINKS = [
  ["/", "Dashboard"],
  ["/secrets", "Secrets"],
  ["/audit", "Audit"],
] as const;

export function Nav({ route }: { route: string }) {
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
    </nav>
  );
}
