const STATUS_PREFIX = "harpoc-bootstrap-v1";

const MAIN: readonly string[] = [
  "exec 2>/dev/null;",
  "LC_ALL=C;",
  "PATH=/usr/sbin:/usr/bin:/sbin:/bin;",
  "export LC_ALL PATH;",
  "umask 077;",
  "say() {",
  "  echo;",
  '  echo "harpoc-bootstrap-v1 $1 $2 $3";',
  "  exit 0;",
  "};",
  "seen() {",
  "  n=0;",
  "  l=;",
  "  while IFS= read -r l; do",
  '    case $l in "$k"|"$k "*|"$k\t"*) n=1 ;; esac;',
  '  done <"$w";',
  '  case $l in "$k"|"$k "*|"$k\t"*) n=1 ;; esac;',
  "};",
  "f=;",
  "k=;",
  "p=;",
  "IFS= read -r f || f=;",
  'c=${f#"harpoc-bootstrap-v1 "};',
  "m=${c#* };",
  "c=${c%% *};",
  'case $f in "harpoc-bootstrap-v1 $c $m") ;; *) c= ;; esac;',
  "case ${#c} in 24) ;; *) c= ;; esac;",
  "case $c in *[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-]*) c= ;; esac;",
  "case $m in key|sudoers) ;; *) c= ;; esac;",
  'case $c in "") say - not_attempted not_attempted ;; esac;',
  "IFS= read -r k || k=;",
  "case $m in sudoers) IFS= read -r p || p= ;; esac;",
  "exec </dev/null;",
  "t=${k%% *};",
  "b=${k#* };",
  "case $t in ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|ssh-rsa|sk-ssh-ed25519@openssh.com|sk-ecdsa-sha2-nistp256@openssh.com) ;; *) k= ;; esac;",
  'case $b in ""|*[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=]*) k= ;; esac;',
  'case $k in "$t $b") ;; *) k= ;; esac;',
  'case $k in "") p=; say "$c" not_attempted not_attempted ;; esac;',
  "d=not_asked;",
  "case $m in sudoers)",
  '  case $p in "") say "$c" not_attempted not_attempted ;; esac;',
  "  d=refused;",
  "  case $(id -u) in",
  "    0) d=present ;;",
  "    *) case $(command -v printf) in printf)",
  '      printf "%s\\n" "$p" | sudo -S -p "" /bin/sh -c "$1" >/dev/null;',
  "      case $? in 40) d=written ;; 41) d=present ;; esac",
  "    ;; esac ;;",
  "  esac;",
  "  p=;",
  '  case $d in refused) say "$c" refused not_attempted ;; esac',
  ";; esac;",
  "unset p;",
  'case $HOME in /*) ;; *) say "$c" "$d" failed ;; esac;',
  "s=$HOME/.ssh;",
  "w=$s/authorized_keys;",
  'mkdir -p "$s";',
  'chmod 700 "$s";',
  'true >>"$w";',
  'chmod 600 "$w";',
  "seen;",
  'case $n in 1) say "$c" "$d" present ;; esac;',
  'case $l in "") ;; *) echo >>"$w" ;; esac;',
  'echo "$k" >>"$w";',
  "seen;",
  'case $n in 1) say "$c" "$d" installed ;; esac;',
  'say "$c" "$d" failed',
];

const ROOT: readonly string[] = [
  "exec </dev/null >/dev/null 2>&1;",
  "PATH=/usr/sbin:/usr/bin:/sbin:/bin;",
  "export PATH;",
  "umask 077;",
  "D=/etc/sudoers.d;",
  "u=$SUDO_UID;",
  'case $u in ""|0*|*[!0123456789]*) exit 43 ;; esac;',
  'r="#$u ALL=(ALL:ALL) NOPASSWD: ALL";',
  "f=$D/harpoc-$u;",
  "t=$f.tmp;",
  "e=0;",
  "l=;",
  "while IFS= read -r l; do",
  '  case $l in "$r") e=1 ;; esac;',
  "done <$f;",
  "case $e in 1) exit 41 ;; esac;",
  "rm -f $t;",
  "set -C;",
  'echo "$r" >$t || exit 44;',
  "visudo -c -f $t || { rm -f $t; exit 45; };",
  "chmod 0440 $t || { rm -f $t; exit 46; };",
  "mv -f $t $f || { rm -f $t; exit 46; };",
  "visudo -c -f /etc/sudoers || { rm -f $f; exit 47; };",
  "exit 40",
];

/**
 * The one remote command of the ssh bootstrap: one argv word and one line, `/bin/sh` by its path,
 * `MAIN` handing `ROOT` to `sudo` as its `$1`. Pinned by its SHA-256; nothing a caller sent is in it.
 */
export const BOOTSTRAP_REMOTE_COMMAND = `/bin/sh -c '${MAIN.join(" ")}' harpoc-bootstrap '${ROOT.join(" ")}'`;

export type BootstrapDropInStatus =
  "written" | "present" | "not_asked" | "not_attempted" | "refused";
export type BootstrapKeyStatus = "installed" | "present" | "not_attempted" | "failed";

/** The two words of the script's status line: what became of the sudoers drop-in and of the key. */
export interface BootstrapStatus {
  dropIn: BootstrapDropInStatus;
  key: BootstrapKeyStatus;
}

const STATUS_PAIRS: readonly BootstrapStatus[] = [
  { dropIn: "not_asked", key: "installed" },
  { dropIn: "not_asked", key: "present" },
  { dropIn: "not_asked", key: "failed" },
  { dropIn: "not_asked", key: "not_attempted" },
  { dropIn: "written", key: "installed" },
  { dropIn: "written", key: "present" },
  { dropIn: "written", key: "failed" },
  { dropIn: "present", key: "installed" },
  { dropIn: "present", key: "present" },
  { dropIn: "present", key: "failed" },
  { dropIn: "not_attempted", key: "not_attempted" },
  { dropIn: "refused", key: "not_attempted" },
];

const FRAME = /^[A-Za-z0-9_-]{24}$/;

/**
 * The script's input: the framing line, the key line, and with a password a third line of its
 * bytes, copied into the returned buffer, which the caller wipes.
 */
export function bootstrapStdin(frame: string, keyLine: string, password?: Buffer): Buffer {
  const mode = password === undefined ? "key" : "sudoers";
  const head = Buffer.from(`${STATUS_PREFIX} ${frame} ${mode}\n${keyLine}\n`);
  if (password === undefined) return head;
  return Buffer.concat([head, password, Buffer.from("\n")]);
}

/**
 * The line as the call's redaction leaves it alone and as it leaves it inside a text that holds a
 * backslash: a backslash anywhere in the stream turns on the redaction's escape-tolerant passes,
 * which change a line that holds `[REDACTED]` once more for a password such as `e`. No form of the
 * password holds a line feed, so the line's own first line feed marks where it begins.
 */
export function redactedLines(line: string, redact: (text: string) => string): string[] {
  const inText = redact(`\\${line}`);
  const start = inText.indexOf("\n");
  return start === -1 ? [redact(line)] : [redact(line), inText.slice(start)];
}

/**
 * The pair of the status line the output ends with, compared after the call's own redaction;
 * `null` for anything but exactly one of the twelve pairs of the fixed set.
 */
export function readBootstrapStatus(
  stdout: string,
  frame: string,
  redact: (text: string) => string,
): BootstrapStatus | null {
  if (!FRAME.test(frame)) return null;
  const found = STATUS_PAIRS.filter((pair) =>
    redactedLines(`\n${STATUS_PREFIX} ${frame} ${pair.dropIn} ${pair.key}\n`, redact).some((line) =>
      stdout.endsWith(line),
    ),
  );
  const [only] = found;
  return found.length === 1 && only !== undefined ? { dropIn: only.dropIn, key: only.key } : null;
}
