// Seeds the fleet's htpasswd-authenticated registry with the image the
// docker-registry opacity arm pulls (the Task 14 rider): the registry starts
// empty, and the arm's `docker pull 127.0.0.1:55000/hello-world:latest`
// through the vault needs an image to succeed. Runs from fleet:up /
// fleet:recreate AFTER `docker compose up --wait`, when the registry is
// already healthy.
//
// Pure Node against the registry HTTP API v2 on purpose — no crane/skopeo
// image, no Docker Hub dependency, no docker CLI state: the pushed image is a
// minimal single-layer amd64/linux image synthesized right here (the
// generate-fixtures.mjs precedent: provisioning is dist-free and in-house).
// Fail-loud provisioning (R-5): any unexpected response exits non-zero with
// the URL and status in the message, never a silent skip.
//
// The registry constants mirror DOCKER_REGISTRY in src/harness/backends.ts
// (drift-pinned by src/harness/backends.test.ts) and the htpasswd baked into
// fixtures/registry/Dockerfile.
import { createHash } from "node:crypto";
import { gzipSync } from "node:zlib";

const REGISTRY = "127.0.0.1:55000";
const USER = "harpoc-docker";
const PASSWORD = "docker-e2e-pw";
const IMAGE = "hello-world:latest";

const [repository, tag] = IMAGE.split(":");
const BASE = `http://${REGISTRY}/v2/${repository}`;
const AUTH = { Authorization: `Basic ${Buffer.from(`${USER}:${PASSWORD}`).toString("base64")}` };

const sha256 = (buf) => `sha256:${createHash("sha256").update(buf).digest("hex")}`;

/** One POSIX ustar entry plus the two zero end-of-archive blocks. */
function tarball(name, data) {
  const header = Buffer.alloc(512);
  header.write(name, 0, 100, "utf8");
  header.write("0000644\0", 100, 8, "ascii"); // mode
  header.write("0000000\0", 108, 8, "ascii"); // uid
  header.write("0000000\0", 116, 8, "ascii"); // gid
  header.write(`${data.length.toString(8).padStart(11, "0")}\0`, 124, 12, "ascii");
  header.write("00000000000\0", 136, 12, "ascii"); // mtime: fixed for determinism
  header.fill(" ", 148, 156); // checksum field spaces while summing
  header.write("0", 156, 1, "ascii"); // typeflag: regular file
  header.write("ustar\0", 257, 6, "ascii");
  header.write("00", 263, 2, "ascii");
  let sum = 0;
  for (const byte of header) sum += byte;
  header.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148, 8, "ascii");
  const pad = (512 - (data.length % 512)) % 512;
  return Buffer.concat([header, data, Buffer.alloc(pad), Buffer.alloc(1024)]);
}

async function request(method, url, { headers = {}, body, okStatuses } = {}) {
  let response;
  try {
    response = await fetch(url, { method, headers, body });
  } catch (cause) {
    console.error(
      `seed-registry: ${method} ${url} failed — is the fleet up?\n` +
        "  run: pnpm --filter @harpoc/e2e fleet:up",
    );
    console.error(cause);
    process.exit(1);
  }
  if (!okStatuses.includes(response.status)) {
    console.error(
      `seed-registry: ${method} ${url} answered ${String(response.status)} ` +
        `(expected ${okStatuses.join("/")})\n  body: ${(await response.text()).slice(0, 300)}`,
    );
    process.exit(1);
  }
  return response;
}

async function pushBlob(bytes, digest, label) {
  const head = await request("HEAD", `${BASE}/blobs/${digest}`, {
    headers: AUTH,
    okStatuses: [200, 404],
  });
  if (head.status === 200) {
    console.log(`seed-registry: ${label} ${digest} already present`);
    return;
  }
  const start = await request("POST", `${BASE}/blobs/uploads/`, {
    headers: AUTH,
    okStatuses: [202],
  });
  const location = start.headers.get("location");
  if (!location) {
    console.error("seed-registry: upload start returned no Location header");
    process.exit(1);
  }
  const target = new URL(location, `http://${REGISTRY}`);
  target.searchParams.set("digest", digest);
  await request("PUT", target.toString(), {
    headers: { ...AUTH, "Content-Type": "application/octet-stream" },
    body: bytes,
    okStatuses: [201],
  });
  console.log(`seed-registry: pushed ${label} ${digest} (${String(bytes.length)} bytes)`);
}

// --- synthesize the image ---------------------------------------------------

const layerTar = tarball("harpoc-e2e-seed", Buffer.from("harpoc e2e registry seed\n", "utf8"));
const layerGz = gzipSync(layerTar);

const arch = { x64: "amd64", arm64: "arm64" }[process.arch] ?? "amd64";
const config = Buffer.from(
  JSON.stringify({
    architecture: arch,
    os: "linux",
    config: {},
    rootfs: { type: "layers", diff_ids: [sha256(layerTar)] },
    history: [{ created_by: "harpoc e2e seed-registry.mjs" }],
  }),
  "utf8",
);

const manifest = Buffer.from(
  JSON.stringify({
    schemaVersion: 2,
    mediaType: "application/vnd.docker.distribution.manifest.v2+json",
    config: {
      mediaType: "application/vnd.docker.container.image.v1+json",
      size: config.length,
      digest: sha256(config),
    },
    layers: [
      {
        mediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip",
        size: layerGz.length,
        digest: sha256(layerGz),
      },
    ],
  }),
  "utf8",
);

// --- push and verify ---------------------------------------------------------

// Auth must be genuinely enforced, or "the credential helper was consulted"
// reads as proven while the registry was open the whole time.
const anonymous = await request("GET", `http://${REGISTRY}/v2/`, { okStatuses: [200, 401] });
if (anonymous.status !== 401) {
  console.error(
    "seed-registry: anonymous GET /v2/ answered 200 — htpasswd auth is NOT enforced; " +
      "rebuild the registry image:\n  pnpm --filter @harpoc/e2e fleet:recreate",
  );
  process.exit(1);
}

await pushBlob(layerGz, sha256(layerGz), "layer");
await pushBlob(config, sha256(config), "config");
await request("PUT", `${BASE}/manifests/${tag}`, {
  headers: { ...AUTH, "Content-Type": "application/vnd.docker.distribution.manifest.v2+json" },
  body: manifest,
  okStatuses: [201],
});

// Read-back: the exact reference the opacity arm pulls resolves with auth.
await request("GET", `${BASE}/manifests/${tag}`, {
  headers: { ...AUTH, Accept: "application/vnd.docker.distribution.manifest.v2+json" },
  okStatuses: [200],
});
console.log(`seed-registry: ${REGISTRY}/${IMAGE} seeded (auth enforced, anonymous /v2/ is 401)`);
