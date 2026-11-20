import { RATE_LIMIT_PROXY_REFUSALS, RATE_LIMIT_PROXY_REFUSAL_WINDOW_MS } from "@harpoc/shared";
import type { CallerContext } from "@harpoc/shared";

interface RefusalWindow {
  opened: number;
  charges: number;
  authorities: Set<string>;
}

export class RefusalBudget {
  private readonly windows = new Map<string, RefusalWindow>();

  constructor(
    private readonly limit = RATE_LIMIT_PROXY_REFUSALS,
    private readonly windowMs = RATE_LIMIT_PROXY_REFUSAL_WINDOW_MS,
    private readonly now: () => number = Date.now,
  ) {}

  private live(key: string): RefusalWindow | undefined {
    const window = this.windows.get(key);
    if (window === undefined || this.now() - window.opened >= this.windowMs) return undefined;
    return window;
  }

  spent(key: string): boolean {
    const window = this.live(key);
    return window !== undefined && window.charges >= this.limit;
  }

  charge(key: string): boolean {
    const now = this.now();
    for (const [held, window] of this.windows) {
      if (now - window.opened >= this.windowMs) this.windows.delete(held);
    }
    let window = this.windows.get(key);
    if (window === undefined) {
      window = { opened: now, charges: 0, authorities: new Set() };
      this.windows.set(key, window);
    }
    if (window.charges >= this.limit) return false;
    window.charges++;
    return window.charges === this.limit;
  }

  refused(key: string, authority: string): boolean {
    return this.live(key)?.authorities.has(authority) === true;
  }

  remember(key: string, authority: string): void {
    const window = this.live(key);
    if (window === undefined || window.authorities.size >= this.limit) return;
    window.authorities.add(authority);
  }
}

export function refusalBudgetKey(
  caller: Pick<CallerContext, "principal_type" | "principal_id">,
): string {
  return `${caller.principal_type}:${caller.principal_id}`;
}
