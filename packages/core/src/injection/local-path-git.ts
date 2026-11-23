import { lstat } from "node:fs/promises";
import { join } from "node:path";

const HFS_IGNORED = /[\u200c-\u200f\u202a-\u202e\u206a-\u206f\ufeff]/g;

/**
 * Whether a file system the vault runs on may read one path segment as `.git`:
 * HFS+ ignores 16 code points anywhere in a name, NTFS reads a name up to its
 * first colon and without its trailing dots and spaces, and `git~<digits>` is
 * an 8.3 short name. A superset of git's `is_hfs_dotgit` and `is_ntfs_dotgit`.
 */
export function isDotGitName(segment: string): boolean {
  const name = segment.replace(HFS_IGNORED, "");
  const colon = name.indexOf(":");
  return /^(?:\.git|git~[0-9]+)$/i.test(
    (colon < 0 ? name : name.slice(0, colon)).replace(/[. ]+$/, ""),
  );
}

export function holdsDotGitName(path: string): boolean {
  return path.split(/[\\/]/).some(isDotGitName);
}

/** `"unreadable"` where a directory has the shape only by counting an entry it could not read. */
export type GitDirectoryShape = "none" | "shape" | "unreadable";

type Presence = "there" | "absent" | "unreadable";

async function presence(path: string): Promise<Presence> {
  try {
    await lstat(path);
    return "there";
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    return code === "ENOENT" || code === "ENOTDIR" ? "absent" : "unreadable";
  }
}

/**
 * Whether git could take `dir` as a git directory, read no narrower than git's
 * own test: `HEAD`, and `commondir` or both `objects` and `refs`, each an entry
 * of any kind that `lstat` finds, never followed and never opened.
 */
export async function gitDirectoryShape(dir: string): Promise<GitDirectoryShape> {
  const head = await presence(join(dir, "HEAD"));
  if (head === "absent") return "none";
  const commondir = await presence(join(dir, "commondir"));
  const objects = await presence(join(dir, "objects"));
  const refs = await presence(join(dir, "refs"));
  const holds = (counted: (entry: Presence) => boolean) =>
    counted(head) && (counted(commondir) || (counted(objects) && counted(refs)));
  if (holds((entry) => entry === "there")) return "shape";
  return holds((entry) => entry !== "absent") ? "unreadable" : "none";
}

export async function hasGitDirectoryShape(dir: string): Promise<boolean> {
  return (await gitDirectoryShape(dir)) !== "none";
}
