/** Accumulates stream output up to a byte cap, flagging truncation. */
export class CappedOutput {
  private readonly chunks: Buffer[] = [];
  private size = 0;
  truncated = false;

  constructor(private readonly max: number) {}

  push(chunk: Buffer): void {
    if (this.size >= this.max) {
      this.truncated = true;
      return;
    }
    const remaining = this.max - this.size;
    if (chunk.length > remaining) {
      this.chunks.push(chunk.subarray(0, remaining));
      this.size = this.max;
      this.truncated = true;
    } else {
      this.chunks.push(chunk);
      this.size += chunk.length;
    }
  }

  toString(): string {
    return Buffer.concat(this.chunks).toString("utf8");
  }
}
