// Fleet preflight: fail loudly BEFORE docker compose where the host provably
// cannot bind the fleet's addresses, with the recovery in the message (R-5:
// fail-loud provisioning, never a silent skip).
//
// The sshd services publish on the loopback aliases 127.0.0.2:22 / 127.0.0.3:22
// (the ssh context is port-22-only, so two servers need two addresses). Linux
// and Windows treat all of 127/8 as loopback; stock macOS configures ONLY
// 127.0.0.1 on lo0, so without a manual alias the compose bring-up dies at port
// publishing with an EADDRNOTAVAIL that names neither the cause nor the fix —
// taking the already-working database arms down with it.
import { createServer } from "node:net";

const SSHD_ALIASES = ["127.0.0.2", "127.0.0.3"];

function canBind(address) {
  return new Promise((resolve) => {
    const srv = createServer();
    srv.unref();
    srv.once("error", () => resolve(false));
    // Port 0: probes the ADDRESS (EADDRNOTAVAIL), never the fleet's port 22 —
    // a running fleet must not fail its own preflight.
    srv.listen({ host: address, port: 0 }, () => {
      srv.close(() => resolve(true));
    });
  });
}

if (process.platform === "darwin") {
  const missing = [];
  for (const address of SSHD_ALIASES) {
    if (!(await canBind(address))) missing.push(address);
  }
  if (missing.length > 0) {
    console.error(
      `fleet preflight: loopback alias${missing.length > 1 ? "es" : ""} ${missing.join(", ")} ` +
        "not configured — stock macOS assigns only 127.0.0.1 to lo0, and the sshd fleet " +
        "publishes on these aliases at port 22.\nAdd them (until reboot) with:\n" +
        missing.map((a) => `  sudo ifconfig lo0 alias ${a} up`).join("\n"),
    );
    process.exit(1);
  }
}
