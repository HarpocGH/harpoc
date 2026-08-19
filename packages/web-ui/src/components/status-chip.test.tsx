import { cleanup, render, screen } from "@testing-library/preact";
import { afterEach, describe, expect, it } from "vitest";
import { StatusChip } from "./status-chip";

afterEach(cleanup);

describe("StatusChip", () => {
  it.each([
    ["active", "ok"],
    ["ok", "ok"],
    ["pending", "warn"],
    ["expired", "bad"],
    ["revoked", "bad"],
    ["failed", "bad"],
  ])("tones %s as %s", (status, tone) => {
    render(<StatusChip status={status} />);
    expect(screen.getByText(status).getAttribute("data-tone")).toBe(tone);
  });

  it("renders an unknown status with the neutral tone, never dropping it", () => {
    render(<StatusChip status="quiesced" />);
    const chip = screen.getByText("quiesced");
    expect(chip.getAttribute("data-tone")).toBe("");
    expect(chip.className).toBe("chip");
  });
});
