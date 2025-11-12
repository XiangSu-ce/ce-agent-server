import { execFile } from "child_process";
import { promisify } from "util";
import { Tool } from "./types.js";
const exec = promisify(execFile);

async function hasRabin2() {
  try {
    await exec("rabin2", ["-V"], { windowsHide: true });
    return true;
  } catch { return false; }
}

async function symbolsJson(path: string) {
  const { stdout } = await exec("rabin2", ["-ij", path], { maxBuffer: 10 * 1024 * 1024, windowsHide: true });
  return JSON.parse(stdout);
}

export const rabin2SymbolsTool: Tool = {
  name: "rabin2_symbols",
  description: "使用 rabin2 解析.so的符号/导入/导出/架构信息（未安装则返回提示）",
  schema: { type: "object", properties: { path: { type: "string" } }, required: ["path"] },
  async handler({ path }) {
    if (!(await hasRabin2())) {
      return { error: "rabin2 未安装，已跳过。请安装 radare2 以启用符号分析。" };
    }
    const data = await symbolsJson(path);
    return {
      arch: data?.bin?.arch,
      bits: data?.bin?.bits,
      os: data?.bin?.os,
      imports: data?.imports ?? [],
      exports: data?.exports ?? [],
      symbols: data?.symbols ?? []
    };
  }
};
