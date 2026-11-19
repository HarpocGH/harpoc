import { RATE_LIMIT_PROXY_REFUSALS, RATE_LIMIT_PROXY_REFUSAL_WINDOW_MS } from "@harpoc/shared";
import type { CallerContext } from "@harpoc/shared";

interface RefusalWindow {
  opened: number;
  charges: number;
}

export class RefusalBudget {
  private readonly windows = new Map<string, RefusalWindow>();

  constructor(
    private readonly limit = RATE_LIMIT_PROXY_REFUSALS,
    private readonly windowMs = RATE_LIMIT_PROXY_REFUSAL_WINDOW_MS,
    private readonly now: () => number = Date.now,
  ) {}

  spent(key: string): boolean {
    const window = this.windows.get(key);
    if (window === undefined) return false;
    return window.charges >= this.limit && this.now() - window.opened < this.windowMs;
  }

  charge(key: string): boolean {
    const now = this.now();
    for (const [held, window] of this.windows) {
      if (now - window.opened >= this.windowMs) this.windows.delete(held);
    }
    let window = this.windows.get(key);
    if (window === undefined) {
      window = { opened: now, charges: 0 };
      this.windows.set(key, window);
    }
    if (window.charges >= this.limit) return false;
    window.charges++;
    return window.charges === this.limit;
  }
}

export function refusalBudgetKey(
  caller: Pick<CallerContext, "principal_type" | "principal_id">,
): string {
  return `${caller.principal_type}:${caller.principal_id}`;
}
