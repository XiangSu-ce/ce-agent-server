import { spawn } from "child_process";

function isMangled(name: string) {
  return /^_Z/.test(name);
}

async function runCxxfilt(cmd: string, names: string[], timeoutMs = 2000): Promise<string[] | null> {
  return new Promise((resolve) => {
    try {
      const p = spawn(cmd, [], { stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
      let out = "";
      let err = "";
      p.stdout.on("data", (d) => { out += d.toString(); });
      p.stderr.on("data", (d) => { err += d.toString(); });
      p.on("error", () => resolve(null));
      p.on("close", (code) => {
        if (code === 0 && out.length > 0) {
          const lines = out.replace(/\r/g, "").split("\n");
          // Ensure same count; if not, bail
          const outLines = lines.filter((_, i) => i < names.length);
          if (outLines.length === names.length) resolve(outLines);
          else resolve(null);
        } else {
          resolve(null);
        }
      });
      // write input
      p.stdin.write(names.join("\n"));
      p.stdin.end();
      // timeout
      setTimeout(() => { try { p.kill(); } catch {} resolve(null); }, timeoutMs).unref();
    } catch { resolve(null); }
  });
}

export async function demangleMany(names: string[]): Promise<Map<string, string>> {
  const unique = Array.from(new Set(names.filter(isMangled)));
  const map = new Map<string, string>();
  if (unique.length === 0) return map;
  // Try llvm-cxxfilt first, then c++filt
  let out = await runCxxfilt("llvm-cxxfilt", unique);
  if (!out) out = await runCxxfilt("c++filt", unique);
  if (out) {
    for (let i = 0; i < unique.length; i++) map.set(unique[i], out[i]);
  }
  return map;
}
