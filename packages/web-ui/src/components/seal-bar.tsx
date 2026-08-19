export function SealBar({ state }: { state: string }) {
  const sealed = state !== "unlocked";
  return (
    <header class="seal-bar" data-state={sealed ? "sealed" : "unlocked"}>
      <span class="state">{sealed ? "SEALED" : "UNLOCKED"}</span>
      <span>harpoc vault</span>
    </header>
  );
}
