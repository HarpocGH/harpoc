// Compiles the win32 job wrapper into dist/win32 after tsc, on Windows hosts
// only (D3 of docs/implementation-plan-win32-job-wrapper-2026-09-10.md), so
// every test process and every vault process on this host finds it built. Off
// Windows, or when the host cannot build it, the runtime compiles on first use
// or runs the taskkill tier; this step never fails the build.
if (process.platform === "win32") {
  try {
    const { resolveJobWrapper } = await import("../dist/injection/win32-job-wrapper.js");
    const resolved = await resolveJobWrapper();
    if ("unavailable" in resolved) {
      console.warn(`[harpoc-job] not prebuilt: ${resolved.unavailable}`);
    } else {
      console.log(`[harpoc-job] ${resolved.exe}`);
    }
  } catch (err) {
    console.warn(`[harpoc-job] not prebuilt: ${err instanceof Error ? err.message : String(err)}`);
  }
}
