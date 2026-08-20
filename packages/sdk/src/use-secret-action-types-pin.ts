import type {
  DockerRegistryAction,
  ImapAction,
  SftpAction,
  SmtpAction,
  UseSecretAction,
  WebsocketAction,
} from "@harpoc/shared";
import type { VaultClient } from "./client.js";

/**
 * Compile-level pin (v1.3 T16, design §7.3): `VaultClient.useSecret`'s
 * `action` parameter is schema-derived — `UseSecretAction` is
 * `z.infer<typeof useSecretActionSchema>` (`packages/shared/src/schemas.ts`)
 * — so every arm the shared discriminated union carries is accepted
 * automatically, including the five v1.3 contexts (smtp/imap/websocket/
 * sftp/docker_registry). There is no SDK-side copy of the action union that
 * could fall behind.
 *
 * Deliberately plain `src/` source, not a `*.test.ts` file: every package's
 * `tsconfig.json` (this one included) excludes `*.test.ts` from
 * `tsc --noEmit`, and vitest's esbuild transform strips type annotations
 * without checking them — a pin written as a vitest test would compile away
 * its own assertions and enforce nothing. This file's only job is to sit in
 * the ordinary `include: ["src"]` program: `pnpm --filter @harpoc/sdk
 * typecheck` (and `build`) fail if any assignment below stops typechecking —
 * e.g. a hand-narrowed `action` parameter, a stale union, or a signature
 * change that drops a new arm. Every declaration here is a `type`, so it has
 * no runtime footprint (erased on build, like `client.ts` itself, which is
 * pure types too and has no dedicated test file for the same reason); the
 * type-checker running over this file *is* the test.
 */

/** True iff every value of `A` is assignable to `B`. */
type Extends<A, B> = A extends B ? true : false;

/** Forces `T` to be exactly `true` — a `false` here fails `tsc --noEmit`. */
type Pin<T extends true> = T;

/** The type `VaultClient.useSecret` actually declares for its `action` parameter. */
type UseSecretActionParam = Parameters<VaultClient["useSecret"]>[1];

// The brief's literal ask: VaultClient.useSecret accepts an SmtpAction.
export type _PinSmtpActionAcceptedByUseSecret = Pin<Extends<SmtpAction, UseSecretActionParam>>;

// The other four v1.3 arms, pinned the same way for completeness.
export type _PinImapActionAcceptedByUseSecret = Pin<Extends<ImapAction, UseSecretActionParam>>;
export type _PinWebsocketActionAcceptedByUseSecret = Pin<
  Extends<WebsocketAction, UseSecretActionParam>
>;
export type _PinSftpActionAcceptedByUseSecret = Pin<Extends<SftpAction, UseSecretActionParam>>;
export type _PinDockerRegistryActionAcceptedByUseSecret = Pin<
  Extends<DockerRegistryAction, UseSecretActionParam>
>;

// Belt-and-suspenders: pin VaultClient.useSecret's parameter directly against
// the shared union type too, in case the interface method is ever detached
// from UseSecretAction (e.g. narrowed to a hand-picked subset).
export type _PinUseSecretActionParamMatchesSharedUnion = Pin<
  Extends<UseSecretAction, UseSecretActionParam>
>;
