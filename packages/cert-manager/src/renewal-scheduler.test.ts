import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { RenewalScheduler } from "./renewal-scheduler.js";

const DAY_MS = 86_400_000;

/**
 * Wide enough to cover both in-call retry delays (1 s + 4 s). The delays are
 * constants, not options, so a failing renewal only settles once the fake
 * clock has been driven past them.
 */
const RETRY_DRIVE_MS = 10_000;

interface StubRow {
  secret_id: string;
  auto_renew: boolean;
  not_after: number | null;
  renew_before_days: number;
}

function row(secretId: string, overrides: Partial<Omit<StubRow, "secret_id">> = {}): StubRow {
  return {
    secret_id: secretId,
    auto_renew: overrides.auto_renew ?? true,
    not_after: overrides.not_after === undefined ? Date.now() + 10 * DAY_MS : overrides.not_after,
    renew_before_days: overrides.renew_before_days ?? 30,
  };
}

function engineWith(rows: StubRow[]) {
  return {
    getExpiringCertificates: vi.fn().mockReturnValue(rows),
    auditCertRenewFailure: vi.fn(),
  };
}

function failingRenewer(message = "acme unreachable") {
  return { renewCertificate: vi.fn().mockRejectedValue(new Error(message)) };
}

function okRenewer() {
  return { renewCertificate: vi.fn().mockResolvedValue(undefined) };
}

/**
 * Run work that may sit on a retry delay: the outcome is captured before the
 * clock moves so a rejection never goes momentarily unhandled.
 */
async function drive<T>(work: Promise<T>): Promise<T> {
  const settled = work.then(
    (value) => ({ ok: true as const, value }),
    (err: unknown) => ({ ok: false as const, err }),
  );
  await vi.advanceTimersByTimeAsync(RETRY_DRIVE_MS);
  const outcome = await settled;
  if (outcome.ok) return outcome.value;
  throw outcome.err;
}

describe("RenewalScheduler", () => {
  let scheduler: RenewalScheduler;

  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    void scheduler?.stop(0);
    vi.useRealTimers();
  });

  it("starts and stops without errors", () => {
    scheduler = new RenewalScheduler(engineWith([]) as never, okRenewer());
    expect(scheduler.isRunning).toBe(false);
    scheduler.start();
    expect(scheduler.isRunning).toBe(true);
    void scheduler.stop();
    expect(scheduler.isRunning).toBe(false);
  });

  it("start is idempotent", () => {
    scheduler = new RenewalScheduler(engineWith([]) as never, okRenewer());
    scheduler.start();
    scheduler.start();
    expect(scheduler.isRunning).toBe(true);
  });

  it("tick queries a full-year window and filters per row", async () => {
    const engine = engineWith([row("c1")]);
    scheduler = new RenewalScheduler(engine as never, okRenewer());
    await scheduler.tick();

    expect(engine.getExpiringCertificates).toHaveBeenCalledWith(366);
  });

  it("tick renews only auto_renew rows inside their per-row window", async () => {
    const engine = engineWith([
      row("due", { not_after: Date.now() + 10 * DAY_MS, renew_before_days: 30 }),
      row("not-yet", { not_after: Date.now() + 100 * DAY_MS, renew_before_days: 30 }),
      row("manual", { auto_renew: false, not_after: Date.now() + 1 * DAY_MS }),
      row("wide-window", { not_after: Date.now() + 100 * DAY_MS, renew_before_days: 120 }),
    ]);
    const renewer = okRenewer();
    scheduler = new RenewalScheduler(engine as never, renewer);
    await scheduler.tick();

    expect(renewer.renewCertificate.mock.calls.map((c) => c[0])).toEqual(["due", "wide-window"]);
  });

  it("tick skips a row without a not_after (CSR pending, nothing issued yet)", async () => {
    const engine = engineWith([row("csr-only", { not_after: null })]);
    const renewer = okRenewer();
    scheduler = new RenewalScheduler(engine as never, renewer);
    await scheduler.tick();

    expect(renewer.renewCertificate).not.toHaveBeenCalled();
  });

  it("tick continues after an individual certificate fails", async () => {
    const engine = engineWith([row("broken"), row("healthy")]);
    const renewer = {
      renewCertificate: vi.fn().mockImplementation(async (id: string) => {
        if (id === "broken") throw new Error("order failed");
      }),
    };
    scheduler = new RenewalScheduler(engine as never, renewer);
    await drive(scheduler.tick());

    const ids = renewer.renewCertificate.mock.calls.map((c) => c[0]);
    expect(ids.filter((id) => id === "broken").length).toBe(3);
    expect(ids.filter((id) => id === "healthy").length).toBe(1);
  });

  it("renewNow delegates to the renewer", async () => {
    const renewer = okRenewer();
    scheduler = new RenewalScheduler(engineWith([]) as never, renewer);
    await scheduler.renewNow("manual-renew");

    expect(renewer.renewCertificate).toHaveBeenCalledExactlyOnceWith("manual-renew");
  });

  it("retries on failure then succeeds", async () => {
    let calls = 0;
    const renewer = {
      renewCertificate: vi.fn().mockImplementation(async () => {
        calls++;
        if (calls < 3) throw new Error("transient");
      }),
    };
    scheduler = new RenewalScheduler(engineWith([]) as never, renewer);
    await drive(scheduler.renewNow("retry-test"));

    expect(calls).toBe(3);
  });

  it("throws after max retries exhausted", async () => {
    const renewer = failingRenewer("persistent failure");
    scheduler = new RenewalScheduler(engineWith([]) as never, renewer);

    await expect(drive(scheduler.renewNow("fail-all"))).rejects.toThrow("persistent failure");
    expect(renewer.renewCertificate).toHaveBeenCalledTimes(3);
  });

  it("spaces the in-call retries by 1 s then 4 s", async () => {
    const renewer = failingRenewer();
    scheduler = new RenewalScheduler(engineWith([]) as never, renewer);
    const settled = scheduler.renewNow("broken").then(
      () => "resolved",
      () => "rejected",
    );

    expect(renewer.renewCertificate).toHaveBeenCalledTimes(1);

    await vi.advanceTimersByTimeAsync(999);
    expect(renewer.renewCertificate).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(renewer.renewCertificate).toHaveBeenCalledTimes(2);

    await vi.advanceTimersByTimeAsync(3_999);
    expect(renewer.renewCertificate).toHaveBeenCalledTimes(2);
    await vi.advanceTimersByTimeAsync(1);
    expect(renewer.renewCertificate).toHaveBeenCalledTimes(3);

    expect(await settled).toBe("rejected");
  });

  it("defaults to an hourly check interval", async () => {
    const engine = engineWith([row("hourly")]);
    scheduler = new RenewalScheduler(engine as never, okRenewer());
    scheduler.start();

    await vi.advanceTimersByTimeAsync(59 * 60 * 1000);
    expect(engine.getExpiringCertificates).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(60 * 1000);
    expect(engine.getExpiringCertificates).toHaveBeenCalledTimes(1);
  });

  it("uses a periodic timer when started", async () => {
    const engine = engineWith([row("periodic")]);
    scheduler = new RenewalScheduler(engine as never, okRenewer(), { checkIntervalMs: 100 });
    scheduler.start();

    await vi.advanceTimersByTimeAsync(250);

    expect(engine.getExpiringCertificates).toHaveBeenCalled();
  });

  it("stop cancels the periodic timer", async () => {
    const engine = engineWith([row("periodic")]);
    scheduler = new RenewalScheduler(engine as never, okRenewer(), { checkIntervalMs: 100 });
    scheduler.start();
    void scheduler.stop();

    await vi.advanceTimersByTimeAsync(500);

    expect(engine.getExpiringCertificates).not.toHaveBeenCalled();
  });

  it("skips interval firings while a previous tick is still running", async () => {
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const engine = engineWith([row("slow")]);
    const renewer = {
      renewCertificate: vi.fn().mockImplementation(async () => {
        await gate;
      }),
    };

    scheduler = new RenewalScheduler(engine as never, renewer, { checkIntervalMs: 100 });
    scheduler.start();

    // Three interval firings while the first tick is blocked on the CA
    await vi.advanceTimersByTimeAsync(350);
    expect(engine.getExpiringCertificates).toHaveBeenCalledTimes(1);
    expect(renewer.renewCertificate).toHaveBeenCalledTimes(1);

    release();
    await vi.advanceTimersByTimeAsync(0);

    await vi.advanceTimersByTimeAsync(100);
    expect(engine.getExpiringCertificates).toHaveBeenCalledTimes(2);
  });
});

describe("RenewalScheduler stop() drain", () => {
  let scheduler: RenewalScheduler;

  afterEach(async () => {
    await scheduler?.stop(0);
  });

  it("stop() resolves only after the in-flight tick stored the issued certificate", async () => {
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let stored = false;
    const renewer = {
      renewCertificate: vi.fn().mockImplementation(async () => {
        await gate;
        stored = true;
      }),
    };
    scheduler = new RenewalScheduler(engineWith([row("s1")]) as never, renewer, {
      checkIntervalMs: 10,
    });
    scheduler.start();
    await vi.waitFor(() => {
      expect(renewer.renewCertificate).toHaveBeenCalled();
    });

    const stopPromise = scheduler.stop();
    let stopResolved = false;
    void stopPromise.then(() => {
      stopResolved = true;
    });
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(stopResolved).toBe(false);
    expect(stored).toBe(false);

    release();
    await stopPromise;
    expect(stored).toBe(true);
  });

  it("the drain is bounded — a hung CA cannot block shutdown", async () => {
    const renewer = { renewCertificate: vi.fn().mockImplementation(() => new Promise(() => {})) };
    scheduler = new RenewalScheduler(engineWith([row("s1")]) as never, renewer, {
      checkIntervalMs: 10,
    });
    scheduler.start();
    await vi.waitFor(() => {
      expect(renewer.renewCertificate).toHaveBeenCalled();
    });

    const start = Date.now();
    await scheduler.stop(200);
    expect(Date.now() - start).toBeLessThan(5_000);
    expect(scheduler.isRunning).toBe(false);
  });

  it("stop() with no tick in flight resolves immediately", async () => {
    scheduler = new RenewalScheduler(engineWith([]) as never, okRenewer());
    scheduler.start();
    await scheduler.stop();
    expect(scheduler.isRunning).toBe(false);
  });
});

describe("RenewalScheduler onRenewError", () => {
  let scheduler: RenewalScheduler;

  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    void scheduler?.stop(0);
    vi.useRealTimers();
  });

  it("invokes onRenewError with secretId and error after retries are exhausted", async () => {
    const renewError = new Error("challenge never validated");
    const reported: { secretId: string; err: unknown }[] = [];
    const renewer = { renewCertificate: vi.fn().mockRejectedValue(renewError) };

    scheduler = new RenewalScheduler(engineWith([row("broken")]) as never, renewer, {
      onRenewError: (secretId, err) => {
        reported.push({ secretId, err });
      },
    });
    await drive(scheduler.tick());

    expect(reported).toEqual([{ secretId: "broken", err: renewError }]);
  });

  it("does not invoke onRenewError on a successful renewal", async () => {
    const onRenewError = vi.fn();
    const renewer = okRenewer();

    scheduler = new RenewalScheduler(engineWith([row("healthy")]) as never, renewer, {
      onRenewError,
    });
    await scheduler.tick();

    expect(renewer.renewCertificate).toHaveBeenCalledOnce();
    expect(onRenewError).not.toHaveBeenCalled();
  });

  it("does not re-invoke onRenewError for a certificate skipped by quarantine", async () => {
    const onRenewError = vi.fn();

    scheduler = new RenewalScheduler(engineWith([row("broken")]) as never, failingRenewer(), {
      checkIntervalMs: 100_000,
      onRenewError,
    });

    await drive(scheduler.tick());
    await drive(scheduler.tick());

    expect(onRenewError).toHaveBeenCalledTimes(1);
  });

  it("writes a failed cert.renew row through the engine once retries are exhausted, before onRenewError", async () => {
    const engine = engineWith([row("broken")]);
    const renewError = new Error("challenge never validated");
    const order: string[] = [];
    engine.auditCertRenewFailure.mockImplementation(() => {
      order.push("audit");
    });

    scheduler = new RenewalScheduler(
      engine as never,
      { renewCertificate: vi.fn().mockRejectedValue(renewError) },
      {
        onRenewError: () => {
          order.push("report");
        },
      },
    );
    await drive(scheduler.tick());

    expect(engine.auditCertRenewFailure).toHaveBeenCalledWith("broken", renewError);
    expect(order).toEqual(["audit", "report"]);
  });

  it("a throwing audit write (sealed engine) does not halt the loop", async () => {
    const engine = engineWith([row("a"), row("b")]);
    engine.auditCertRenewFailure.mockImplementation(() => {
      throw new Error("vault is locked");
    });
    const renewer = failingRenewer();

    scheduler = new RenewalScheduler(engine as never, renewer);
    await drive(scheduler.tick());

    expect(renewer.renewCertificate).toHaveBeenCalledTimes(6);
  });

  it("renewNow rethrows to the caller without invoking onRenewError", async () => {
    const onRenewError = vi.fn();
    scheduler = new RenewalScheduler(engineWith([]) as never, failingRenewer("still dead"), {
      onRenewError,
    });

    await expect(drive(scheduler.renewNow("manual"))).rejects.toThrow("still dead");
    expect(onRenewError).not.toHaveBeenCalled();
  });
});

describe("RenewalScheduler failure quarantine", () => {
  let scheduler: RenewalScheduler;

  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    void scheduler?.stop(0);
    vi.useRealTimers();
  });

  it("skips a failed certificate until its backoff window elapses, then doubles it", async () => {
    const renewer = failingRenewer();
    scheduler = new RenewalScheduler(engineWith([row("broken")]) as never, renewer, {
      checkIntervalMs: 100_000,
    });

    // Attempts land at t = 0 / 1_000 / 5_000; the failure is recorded at
    // t = 5_000 and quarantines for 100_000 * 2^1 = 200_000 ms.
    await drive(scheduler.tick());
    expect(renewer.renewCertificate).toHaveBeenCalledTimes(3);

    await vi.advanceTimersByTimeAsync(190_000); // t = 200_000, still inside the window
    await drive(scheduler.tick());
    expect(renewer.renewCertificate).toHaveBeenCalledTimes(3);

    // t = 210_000, past nextAttemptAt = 205_000: retried, backoff now 400_000
    await drive(scheduler.tick());
    expect(renewer.renewCertificate).toHaveBeenCalledTimes(6);

    await vi.advanceTimersByTimeAsync(390_000); // t = 610_000 < 615_000
    await drive(scheduler.tick());
    expect(renewer.renewCertificate).toHaveBeenCalledTimes(6);

    await drive(scheduler.tick()); // t = 620_000, past it
    expect(renewer.renewCertificate).toHaveBeenCalledTimes(9);
  });

  it("caps the backoff at 24 hours", async () => {
    const renewer = failingRenewer();
    scheduler = new RenewalScheduler(engineWith([row("broken")]) as never, renewer, {
      checkIntervalMs: 100 * DAY_MS,
    });

    // Uncapped the first failure would quarantine for 200 days; the cap holds
    // it to 24 h from the moment of failure (t = 5_000).
    await drive(scheduler.tick());
    expect(renewer.renewCertificate).toHaveBeenCalledTimes(3);

    await vi.advanceTimersByTimeAsync(DAY_MS - 10_000); // t = 86_400_000 < 86_405_000
    await drive(scheduler.tick());
    expect(renewer.renewCertificate).toHaveBeenCalledTimes(3);

    await drive(scheduler.tick()); // t = 86_410_000, past the cap
    expect(renewer.renewCertificate).toHaveBeenCalledTimes(6);
  });

  it("a successful renewal clears the quarantine, resetting the backoff", async () => {
    let fail = true;
    const renewer = {
      renewCertificate: vi.fn().mockImplementation(async () => {
        if (fail) throw new Error("transient");
      }),
    };
    scheduler = new RenewalScheduler(engineWith([row("flaky")]) as never, renewer, {
      checkIntervalMs: 100_000,
    });

    await drive(scheduler.tick()); // quarantined for 200_000 from t = 5_000
    expect(renewer.renewCertificate).toHaveBeenCalledTimes(3);

    fail = false;
    await vi.advanceTimersByTimeAsync(300_000); // t = 310_000, window elapsed
    await drive(scheduler.tick());
    expect(renewer.renewCertificate).toHaveBeenCalledTimes(4);

    // The next failure counts as the first one again — backoff is the base
    // 200_000, not the doubled 400_000 a surviving entry would produce.
    fail = true;
    await drive(scheduler.tick()); // t = 320_000; fails, nextAttemptAt = 525_000
    expect(renewer.renewCertificate).toHaveBeenCalledTimes(7);

    await vi.advanceTimersByTimeAsync(200_000); // t = 530_000
    await drive(scheduler.tick());
    expect(renewer.renewCertificate).toHaveBeenCalledTimes(10);
  });

  it("renewNow bypasses the quarantine (explicit operator action)", async () => {
    const renewer = failingRenewer();
    scheduler = new RenewalScheduler(engineWith([row("broken")]) as never, renewer, {
      checkIntervalMs: 100_000,
    });

    await drive(scheduler.tick());
    expect(renewer.renewCertificate).toHaveBeenCalledTimes(3);

    await expect(drive(scheduler.renewNow("broken"))).rejects.toThrow("acme unreachable");
    expect(renewer.renewCertificate).toHaveBeenCalledTimes(6);
  });

  it("one quarantined certificate does not block others", async () => {
    const engine = engineWith([row("broken"), row("healthy")]);
    const renewer = {
      renewCertificate: vi.fn().mockImplementation(async (id: string) => {
        if (id === "broken") throw new Error("dead");
      }),
    };
    scheduler = new RenewalScheduler(engine as never, renewer, { checkIntervalMs: 100_000 });

    await drive(scheduler.tick());
    await drive(scheduler.tick());

    const ids = renewer.renewCertificate.mock.calls.map((c) => c[0]);
    expect(ids.filter((id) => id === "healthy").length).toBe(2);
    expect(ids.filter((id) => id === "broken").length).toBe(3);
  });
});
