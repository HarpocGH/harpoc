import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/preact";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useAsync } from "./hooks";

function Probe({ load, dep = 0 }: { load: () => Promise<string>; dep?: number }) {
  const { data, error, reload } = useAsync(load, [dep]);
  return (
    <div>
      <span data-testid="data">{data ?? "-"}</span>
      <span data-testid="error">{error?.message ?? "-"}</span>
      <button onClick={reload}>reload</button>
    </div>
  );
}

const text = (id: string): string => screen.getByTestId(id).textContent ?? "";

afterEach(cleanup);

describe("useAsync", () => {
  it("exposes the resolved value", async () => {
    render(<Probe load={() => Promise.resolve("v1")} />);
    await waitFor(() => expect(text("data")).toBe("v1"));
    expect(text("error")).toBe("-");
  });

  it("exposes a rejection as an Error", async () => {
    render(<Probe load={() => Promise.reject(new Error("boom"))} />);
    await waitFor(() => expect(text("error")).toBe("boom"));
  });

  it("wraps a non-Error rejection", async () => {
    render(<Probe load={() => Promise.reject("plain string")} />);
    await waitFor(() => expect(text("error")).toBe("plain string"));
  });

  it("re-runs the loader on reload", async () => {
    let n = 0;
    const load = vi.fn(() => Promise.resolve(`v${String(++n)}`));
    render(<Probe load={load} />);
    await waitFor(() => expect(text("data")).toBe("v1"));
    fireEvent.click(screen.getByText("reload"));
    await waitFor(() => expect(text("data")).toBe("v2"));
    expect(load).toHaveBeenCalledTimes(2);
  });

  it("re-runs when a dep changes and not when it does not", async () => {
    const load = vi.fn(() => Promise.resolve("v"));
    const { rerender } = render(<Probe load={load} dep={1} />);
    await waitFor(() => expect(load).toHaveBeenCalledTimes(1));
    rerender(<Probe load={load} dep={1} />);
    expect(load).toHaveBeenCalledTimes(1);
    rerender(<Probe load={load} dep={2} />);
    await waitFor(() => expect(load).toHaveBeenCalledTimes(2));
  });

  it("clears a stale error when the loader re-runs", async () => {
    let fail = true;
    const load = () => (fail ? Promise.reject(new Error("boom")) : Promise.resolve("ok"));
    render(<Probe load={load} />);
    await waitFor(() => expect(text("error")).toBe("boom"));
    fail = false;
    fireEvent.click(screen.getByText("reload"));
    await waitFor(() => expect(text("data")).toBe("ok"));
    expect(text("error")).toBe("-");
  });

  it("drops stale data while a dep-changed re-run is in flight", async () => {
    // A changed dep means the question changed — a detail page keyed on a
    // handle asks about a different secret entirely — so the previous value
    // must not stay on screen as if it were the current one.
    let settle: (v: string) => void = () => undefined;
    const load = vi
      .fn()
      .mockImplementationOnce(() => Promise.resolve("v1"))
      .mockImplementationOnce(() => new Promise<string>((r) => (settle = r)));
    const { rerender } = render(<Probe load={load} dep={1} />);
    await waitFor(() => expect(text("data")).toBe("v1"));

    rerender(<Probe load={load} dep={2} />);
    await waitFor(() => expect(text("data")).toBe("-"));
    settle("v2");
    await waitFor(() => expect(text("data")).toBe("v2"));
  });

  it("keeps the current data while a same-deps reload is in flight", async () => {
    // A reload asks the SAME question again — after a mutation, typically — so
    // the previous answer is still the best one on screen until the new one
    // lands. Blanking it collapses a detail page to its "Loading…" branch on
    // every save, which reads as if the secret had gone away.
    let settle: (v: string) => void = () => undefined;
    const load = vi
      .fn()
      .mockImplementationOnce(() => Promise.resolve("v1"))
      .mockImplementationOnce(() => new Promise<string>((r) => (settle = r)));
    render(<Probe load={load} dep={1} />);
    await waitFor(() => expect(text("data")).toBe("v1"));

    fireEvent.click(screen.getByText("reload"));
    await waitFor(() => expect(load).toHaveBeenCalledTimes(2));
    expect(text("data")).toBe("v1");
    settle("v2");
    await waitFor(() => expect(text("data")).toBe("v2"));
  });

  it("drops a response that lands after unmount", async () => {
    let settle: (v: string) => void = () => undefined;
    const { unmount } = render(<Probe load={() => new Promise<string>((r) => (settle = r))} />);
    unmount();
    settle("late");
    // No unmounted-component state update: the assertion is that nothing throws
    // and no stale node reappears in the document.
    await Promise.resolve();
    expect(screen.queryByTestId("data")).toBeNull();
  });
});
