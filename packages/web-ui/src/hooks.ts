import { useCallback, useEffect, useRef, useState } from "preact/hooks";

export interface AsyncState<T> {
  data: T | null;
  error: Error | null;
  reload: () => void;
}

/**
 * Load-on-mount with a caller-supplied cache key. A superseded load is dropped
 * rather than cancelled — the `live` flag keeps a slow first response from
 * overwriting a newer one.
 *
 * A changed dep clears `data`: the question itself changed — another handle is
 * another secret — and leaving the previous answer on screen labels it with the
 * new key. A `reload()` does not: it asks the SAME question again, typically
 * right after a mutation, so the current answer stays until the new one lands
 * rather than collapsing the page to its loading branch on every save. `error`
 * is cleared either way — a stale refusal outlives nothing.
 */
export function useAsync<T>(load: () => Promise<T>, deps: unknown[]): AsyncState<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const [tick, setTick] = useState(0);
  const previousDeps = useRef<unknown[] | null>(null);
  const reload = useCallback(() => setTick((t) => t + 1), []);
  useEffect(() => {
    let live = true;
    const previous = previousDeps.current;
    const depsChanged =
      previous === null ||
      previous.length !== deps.length ||
      deps.some((dep, i) => !Object.is(dep, previous[i]));
    previousDeps.current = deps;
    if (depsChanged) setData(null);
    setError(null);
    load().then(
      (result) => {
        if (live) setData(result);
      },
      (err: unknown) => {
        if (live) setError(err instanceof Error ? err : new Error(String(err)));
      },
    );
    return () => {
      live = false;
    };
  }, [tick, ...deps]);
  return { data, error, reload };
}
