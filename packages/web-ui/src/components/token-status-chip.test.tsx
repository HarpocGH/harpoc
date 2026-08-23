import { cleanup, render, screen } from "@testing-library/preact";
import { afterEach, describe, expect, it } from "vitest";
import { StatusChip } from "./status-chip";
import { TokenStatusChip } from "./token-status-chip";

afterEach(cleanup);

describe("TokenStatusChip", () => {
  it.each([
    ["active", "ok"],
    ["revoked", "bad"],
    ["expired", ""],
  ] as const)("tones %s as %s", (status, tone) => {
    render(<TokenStatusChip status={status} />);
    expect(screen.getByText(status).getAttribute("data-tone")).toBe(tone);
  });

  it("keeps an expired token neutral where the shared chip would call it a fault", () => {
    render(<StatusChip status="expired" />);
    expect(screen.getByText("expired").getAttribute("data-tone")).toBe("bad");
  });
});
