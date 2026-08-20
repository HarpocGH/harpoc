// SMTP + IMAP mail backend for the v1.3 smtp and imap injection contexts.
//
// A pair of TLS servers — SMTPS on 8465, IMAPS on 8993 — implementing the
// protocol subset the vault's in-house SMTP/IMAP clients drive (design §4.2):
// SMTP EHLO → AUTH (PLAIN or LOGIN) → MAIL/RCPT/DATA → QUIT, and IMAP
// greeting → CAPABILITY → LOGIN → EXAMINE/SELECT → UID SEARCH/FETCH → LOGOUT.
// It accepts any credential and never reflects it: the vault's opacity claim is
// about the RESULT the vault authors, not about what the server does with the
// AUTH bytes, so this backend's job is only to complete a clean transaction.
//
// TLS uses the SAN-covered localhost leaf the echo-https fixture presents
// (mounted at /pki), so trust rides the fixture CA via NODE_EXTRA_CA_CERTS, the
// same lever the http and database TLS paths use. No new PKI leaf is generated.
//
// Provisional (D8): the protocol subset is validated at the owed Linux fleet
// run, not on the Windows collection-verify pass. Keep it minimal and forgiving.
import { readFileSync } from "node:fs";
import { createServer } from "node:tls";

const SMTP_PORT = Number(process.env.SMTP_PORT ?? 8465);
const IMAP_PORT = Number(process.env.IMAP_PORT ?? 8993);

const tlsOptions = {
  key: readFileSync("/pki/echo-https.key"),
  cert: readFileSync("/pki/echo-https.crt"),
};

// --- SMTP (SMTPS) ----------------------------------------------------------

function handleSmtp(socket) {
  socket.setEncoding("utf8");
  let buf = "";
  let dataMode = false;
  let authState = null; // null | "username" | "password"
  socket.write("220 harpoc-e2e-mail ESMTP ready\r\n");

  socket.on("data", (chunk) => {
    buf += chunk;
    let idx;
    while ((idx = buf.indexOf("\r\n")) >= 0) {
      const line = buf.slice(0, idx);
      buf = buf.slice(idx + 2);

      if (dataMode) {
        if (line === ".") {
          dataMode = false;
          socket.write("250 2.0.0 Ok: queued\r\n");
        }
        continue;
      }
      if (authState === "username") {
        authState = "password";
        socket.write("334 UGFzc3dvcmQ6\r\n"); // base64("Password:")
        continue;
      }
      if (authState === "password") {
        authState = null;
        socket.write("235 2.7.0 Authentication successful\r\n");
        continue;
      }

      const upper = line.toUpperCase();
      if (upper.startsWith("EHLO") || upper.startsWith("HELO")) {
        socket.write(
          "250-harpoc-e2e-mail\r\n250-AUTH PLAIN LOGIN\r\n250-8BITMIME\r\n250 SMTPUTF8\r\n",
        );
      } else if (upper.startsWith("AUTH PLAIN")) {
        socket.write("235 2.7.0 Authentication successful\r\n");
      } else if (upper === "AUTH LOGIN") {
        authState = "username";
        socket.write("334 VXNlcm5hbWU6\r\n"); // base64("Username:")
      } else if (upper.startsWith("MAIL FROM")) {
        socket.write("250 2.1.0 Ok\r\n");
      } else if (upper.startsWith("RCPT TO")) {
        socket.write("250 2.1.5 Ok\r\n");
      } else if (upper === "DATA") {
        dataMode = true;
        socket.write("354 End data with <CR><LF>.<CR><LF>\r\n");
      } else if (upper === "QUIT") {
        socket.write("221 2.0.0 Bye\r\n");
        socket.end();
      } else {
        socket.write("250 2.0.0 Ok\r\n");
      }
    }
  });
  socket.on("error", () => {});
}

// --- IMAP (IMAPS) ----------------------------------------------------------

function handleImapLine(socket, line) {
  const sp = line.indexOf(" ");
  const tag = sp < 0 ? line : line.slice(0, sp);
  const rest = sp < 0 ? "" : line.slice(sp + 1);
  const restUpper = rest.toUpperCase();
  const verb = (restUpper.split(" ")[0] ?? "").trim();

  if (verb === "CAPABILITY") {
    socket.write("* CAPABILITY IMAP4rev1 LITERAL+ UIDPLUS\r\n");
    socket.write(`${tag} OK CAPABILITY completed\r\n`);
  } else if (verb === "LOGIN") {
    socket.write(`${tag} OK LOGIN completed\r\n`);
  } else if (verb === "EXAMINE" || verb === "SELECT") {
    socket.write("* 0 EXISTS\r\n* 0 RECENT\r\n");
    socket.write("* OK [UIDVALIDITY 1] UIDs valid\r\n* OK [UIDNEXT 1] Predicted next UID\r\n");
    const mode = verb === "EXAMINE" ? "[READ-ONLY] " : "[READ-WRITE] ";
    socket.write(`${tag} OK ${mode}${verb} completed\r\n`);
  } else if (restUpper.startsWith("UID SEARCH") || verb === "SEARCH") {
    socket.write("* SEARCH\r\n");
    socket.write(`${tag} OK SEARCH completed\r\n`);
  } else if (restUpper.startsWith("UID FETCH") || verb === "FETCH") {
    socket.write(`${tag} OK FETCH completed\r\n`);
  } else if (verb === "LOGOUT") {
    socket.write("* BYE logging out\r\n");
    socket.write(`${tag} OK LOGOUT completed\r\n`);
    socket.end();
  } else {
    socket.write(`${tag} OK completed\r\n`);
  }
}

function handleImap(socket) {
  socket.setEncoding("utf8");
  let buf = "";
  let literalRemaining = 0;
  socket.write("* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN LOGIN] harpoc-e2e-mail ready\r\n");

  socket.on("data", (chunk) => {
    buf += chunk;
    for (;;) {
      if (literalRemaining > 0) {
        if (buf.length < literalRemaining) return;
        buf = buf.slice(literalRemaining);
        literalRemaining = 0;
      }
      const idx = buf.indexOf("\r\n");
      if (idx < 0) return;
      const line = buf.slice(0, idx);
      buf = buf.slice(idx + 2);

      // A synchronizing literal (`{n}`, not the non-synchronizing `{n+}`) is
      // acknowledged with a continuation before its octets arrive. The vault's
      // credentials are quotable, so this branch is defensive only.
      const lit = /\{(\d+)\}$/.exec(line);
      if (lit) {
        literalRemaining = Number(lit[1]);
        socket.write("+ OK\r\n");
        continue;
      }
      handleImapLine(socket, line);
    }
  });
  socket.on("error", () => {});
}

// --- Listeners -------------------------------------------------------------

createServer(tlsOptions, handleSmtp).listen(SMTP_PORT, "0.0.0.0", () => {
  process.stdout.write(`SMTPS listening ${String(SMTP_PORT)}\n`);
});

createServer(tlsOptions, handleImap).listen(IMAP_PORT, "0.0.0.0", () => {
  process.stdout.write(`IMAPS listening ${String(IMAP_PORT)}\n`);
});
