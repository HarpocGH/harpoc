/**
 * The listener vocabulary the `server.start` / `server.stop` audit rows carry
 * (D9, 2026-09-06). Declared once here because core, cli and mcp-server each
 * wrote the same two unions inline: an operator reading rows written by all
 * three surfaces has to be able to trust that they agree, and mcp-server's
 * deliberate two-member narrowing is then an `Extract` of this list rather
 * than a second list.
 */

/** Every transport a Harpoc listener runs. */
export const SERVER_TRANSPORTS = ["stdio", "http", "rest"] as const;

/** Every reason a Harpoc listener stops. */
export const SERVER_STOP_TRIGGERS = ["SIGINT", "SIGTERM", "transport_closed"] as const;

export type ServerTransport = (typeof SERVER_TRANSPORTS)[number];
export type ServerStopTrigger = (typeof SERVER_STOP_TRIGGERS)[number];
