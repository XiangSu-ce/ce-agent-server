import { promises as fs } from "fs";
import { Tool } from "./types.js";

function extractASCII(buf: Buffer, min = 4) {
  const out: string[] = [];
  let cur: number[] = [];
  const push = () => {
    if (cur.length >= min) out.push(Buffer.from(cur).toString("ascii"));
    cur = [];
  };
  for (let i = 0; i < buf.length; i++) {
    const c = buf[i];
    if (c >= 0x20 && c <= 0x7E) cur.push(c);
    else push();
  }
  push();
  return out;
}

function extractUTF16LE(buf: Buffer, min = 4) {
  const out: string[] = [];
  let cur: number[] = [];
  const push = () => {
    if (cur.length >= min) out.push(Buffer.from(cur).toString("utf16le"));
    cur = [];
  };
  for (let i = 0; i + 1 < buf.length; i += 2) {
    const lo = buf[i], hi = buf[i + 1];
    if (hi === 0x00 && lo >= 0x20 && lo <= 0x7E) {
      cur.push(lo, hi);
    } else {
      push();
    }
  }
  push();
  return out;
}

export const stringsTool: Tool = {
  name: "binary_strings",
  description: "提取二进制中的可打印字符串（支持.so），返回前N条与长度排序",
  schema: {
    type: "object",
    properties: {
      path: { type: "string" },
      minLen: { type: "number", default: 4 },
      topK: { type: "number", default: 200 }
    },
    required: ["path"]
  },
  async handler({ path, minLen = 4, topK = 200 }) {
    const buf = await fs.readFile(path);
    const set = new Set<string>([
      ...extractASCII(buf, minLen),
      ...extractUTF16LE(buf, minLen)
    ]);
    const arr = [...set].sort((a, b) => b.length - a.length).slice(0, topK);
    return { count: arr.length, strings: arr };
  }
};
