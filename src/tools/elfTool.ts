import { promises as fs } from "fs";
import { Tool } from "./types.js";

// Minimal ELF parser for headers/sections/dynamic/imports/relocations
// Supports 32/64-bit, little/big endian. Focused on typical Android .so (LE).

const EI_CLASS = 4; // 1=32, 2=64
const EI_DATA = 5;  // 1=LE, 2=BE

const ET_DYN = 3;

const EM_NAMES: Record<number, string> = {
  3: "EM_386",
  8: "EM_MIPS",
  40: "EM_ARM",
  62: "EM_X86_64",
  183: "EM_AARCH64",
};

const SHT_DYNSYM = 11;
const SHT_DYNAMIC = 6;
const SHT_STRTAB = 3;
const SHT_RELA = 4;
const SHT_REL = 9;

const DT_NULL = 0;
const DT_NEEDED = 1;
const DT_STRTAB = 5;
const DT_SYMTAB = 6;
const DT_SONAME = 14;
const DT_RPATH = 15;
const DT_RUNPATH = 29;
const DT_JMPREL = 23;
const DT_PLTREL = 20; // REL or RELA
const DT_PLTRELSZ = 2; // some toolchains use 2? Actually 2 is DT_PLTRELSZ? (real value is 2)

function toHex(n: number) { return `0x${n.toString(16)}`; }

class Reader {
  dv: DataView;
  little: boolean;
  constructor(buf: Buffer, little: boolean) {
    this.dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    this.little = little;
  }
  u8(o: number) { return this.dv.getUint8(o); }
  u16(o: number) { return this.dv.getUint16(o, this.little); }
  u32(o: number) { return this.dv.getUint32(o, this.little); }
  u64(o: number) { return Number(this.dv.getBigUint64(o, this.little)); }
}

function parseHeader(buf: Buffer) {
  if (buf.length < 0x40) throw new Error("文件过小，非有效ELF");
  if (!(buf[0] === 0x7F && buf[1] === 0x45 && buf[2] === 0x4C && buf[3] === 0x46)) {
    throw new Error("魔数不匹配，非ELF");
  }
  const eiClass = buf[EI_CLASS];
  const eiData = buf[EI_DATA];
  const little = eiData === 1;
  const r = new Reader(buf, little);
  const is64 = eiClass === 2;
  const e_type = r.u16(0x10);
  const e_machine = r.u16(0x12);
  const e_version = r.u32(0x14);
  const e_entry = is64 ? r.u64(0x18) : r.u32(0x18);
  const e_phoff = is64 ? r.u64(0x20) : r.u32(0x1C);
  const e_shoff = is64 ? r.u64(0x28) : r.u32(0x20);
  const e_flags = is64 ? r.u32(0x30) : r.u32(0x24);
  const e_ehsize = is64 ? r.u16(0x34) : r.u16(0x28);
  const e_phentsize = is64 ? r.u16(0x36) : r.u16(0x2A);
  const e_phnum = is64 ? r.u16(0x38) : r.u16(0x2C);
  const e_shentsize = is64 ? r.u16(0x3A) : r.u16(0x2E);
  const e_shnum = is64 ? r.u16(0x3C) : r.u16(0x30);
  const e_shstrndx = is64 ? r.u16(0x3E) : r.u16(0x32);
  return {
    is64, little, e_type, e_machine, e_version, e_entry,
    e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx,
    r,
  };
}

function parseProgramHeaders(buf: Buffer, H: any) {
  const { r, is64, e_phoff, e_phentsize, e_phnum } = H;
  const ph: any[] = [];
  for (let i = 0; i < e_phnum; i++) {
    const off = e_phoff + i * e_phentsize;
    if (off + e_phentsize > buf.length) break;
    if (is64) {
      const p_type = r.u32(off + 0);
      const p_flags = r.u32(off + 4);
      const p_offset = r.u64(off + 8);
      const p_vaddr = r.u64(off + 16);
      const p_paddr = r.u64(off + 24);
      const p_filesz = r.u64(off + 32);
      const p_memsz = r.u64(off + 40);
      const p_align = r.u64(off + 48);
      ph.push({ p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align });
    } else {
      const p_type = r.u32(off + 0);
      const p_offset = r.u32(off + 4);
      const p_vaddr = r.u32(off + 8);
      const p_paddr = r.u32(off + 12);
      const p_filesz = r.u32(off + 16);
      const p_memsz = r.u32(off + 20);
      const p_flags = r.u32(off + 24);
      const p_align = r.u32(off + 28);
      ph.push({ p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align });
    }
  }
  return ph;
}

function parseSectionHeaders(buf: Buffer, H: any) {
  const { r, is64, e_shoff, e_shentsize, e_shnum } = H;
  const sh: any[] = [];
  for (let i = 0; i < e_shnum; i++) {
    const off = e_shoff + i * e_shentsize;
    if (off + e_shentsize > buf.length) break;
    if (is64) {
      const sh_name = r.u32(off + 0);
      const sh_type = r.u32(off + 4);
      const sh_flags = r.u64(off + 8);
      const sh_addr = r.u64(off + 16);
      const sh_offset = r.u64(off + 24);
      const sh_size = r.u64(off + 32);
      const sh_link = r.u32(off + 40);
      const sh_info = r.u32(off + 44);
      const sh_addralign = r.u64(off + 48);
      const sh_entsize = r.u64(off + 56);
      sh.push({ sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize });
    } else {
      const sh_name = r.u32(off + 0);
      const sh_type = r.u32(off + 4);
      const sh_flags = r.u32(off + 8);
      const sh_addr = r.u32(off + 12);
      const sh_offset = r.u32(off + 16);
      const sh_size = r.u32(off + 20);
      const sh_link = r.u32(off + 24);
      const sh_info = r.u32(off + 28);
      const sh_addralign = r.u32(off + 32);
      const sh_entsize = r.u32(off + 36);
      sh.push({ sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize });
    }
  }
  return sh;
}

function readStr(buf: Buffer, off: number) {
  let i = off;
  const bytes: number[] = [];
  while (i < buf.length) {
    const b = buf[i++];
    if (b === 0) break;
    bytes.push(b);
  }
  return Buffer.from(bytes).toString("utf8");
}

function attachSectionNames(buf: Buffer, H: any, sh: any[]) {
  const shstr = sh[H.e_shstrndx];
  const names: string[] = [];
  if (!shstr || shstr.sh_offset + shstr.sh_size > buf.length) return sh.map((s) => ({ ...s, name: "" }));
  const strtab = buf.subarray(shstr.sh_offset, shstr.sh_offset + shstr.sh_size);
  for (const s of sh) {
    const name = s.sh_name ? readStr(strtab, s.sh_name) : "";
    names.push(name);
  }
  return sh.map((s, i) => ({ ...s, name: names[i] }));
}

function findSection(shWithNames: any[], name: string) {
  return shWithNames.find(s => s.name === name);
}

function parseDynStrings(buf: Buffer, dynstr: any) {
  if (!dynstr) return (off: number) => "";
  const tab = buf.subarray(dynstr.sh_offset, dynstr.sh_offset + dynstr.sh_size);
  return (off: number) => readStr(tab, off);
}

function parseDynsym(buf: Buffer, H: any, shNamed: any[], dynsym: any, dynstr: any) {
  if (!dynsym || !dynstr) return [] as any[];
  const { is64, r } = H;
  const base = dynsym.sh_offset;
  const entsize = dynsym.sh_entsize || (is64 ? 24 : 16);
  const count = Math.floor(dynsym.sh_size / entsize);
  const out: any[] = [];
  const dynStrTab = buf.subarray(dynstr.sh_offset, dynstr.sh_offset + dynstr.sh_size);
  for (let i = 0; i < count; i++) {
    const off = base + i * entsize;
    if (is64) {
      const st_name = r.u32(off + 0);
      const st_info = r.u8(off + 4);
      const st_bind = st_info >> 4;
      const st_type = st_info & 0x0F;
      const st_other = r.u8(off + 5);
      const st_shndx = r.u16(off + 6);
      const st_value = H.r.u64(off + 8);
      const st_size = H.r.u64(off + 16);
      const name = st_name ? readStr(dynStrTab, st_name) : "";
      out.push({ st_name, st_info, st_bind, st_type, st_other, st_shndx, st_value, st_size, name });
    } else {
      const st_name = r.u32(off + 0);
      const st_value = r.u32(off + 4);
      const st_size = r.u32(off + 8);
      const st_info = r.u8(off + 12);
      const st_bind = st_info >> 4;
      const st_type = st_info & 0x0F;
      const st_other = r.u8(off + 13);
      const st_shndx = r.u16(off + 14);
      const name = st_name ? readStr(dynStrTab, st_name) : "";
      out.push({ st_name, st_info, st_bind, st_type, st_other, st_shndx, st_value, st_size, name });
    }
  }
  return out;
}

function parseRelocs(buf: Buffer, H: any, relSec: any, isRela: boolean) {
  if (!relSec) return [] as any[];
  const { is64, r } = H;
  const base = relSec.sh_offset;
  const entsize = relSec.sh_entsize || (isRela ? (is64 ? 24 : 12) : (is64 ? 16 : 8));
  const count = Math.floor(relSec.sh_size / entsize);
  const out: any[] = [];
  for (let i = 0; i < count; i++) {
    const off = base + i * entsize;
    if (isRela) {
      if (is64) {
        const r_offset = r.u64(off + 0);
        const r_info64 = BigInt(r.u64(off + 8));
        const r_type = Number(r_info64 & BigInt(0xFFFFFFFF));
        const r_sym = Number(r_info64 >> BigInt(32));
        const r_addend = r.u64(off + 16);
        out.push({ r_offset, r_type, r_sym, r_addend });
      } else {
        const r_offset = r.u32(off + 0);
        const r_info = r.u32(off + 4);
        const r_type = r_info & 0xFF;
        const r_sym = r_info >>> 8;
        const r_addend = r.u32(off + 8);
        out.push({ r_offset, r_type, r_sym, r_addend });
      }
    } else {
      if (is64) {
        const r_offset = r.u64(off + 0);
        const r_info64 = BigInt(r.u64(off + 8));
        const r_type = Number(r_info64 & BigInt(0xFFFFFFFF));
        const r_sym = Number(r_info64 >> BigInt(32));
        out.push({ r_offset, r_type, r_sym });
      } else {
        const r_offset = r.u32(off + 0);
        const r_info = r.u32(off + 4);
        const r_type = r_info & 0xFF;
        const r_sym = r_info >>> 8;
        out.push({ r_offset, r_type, r_sym });
      }
    }
  }
  return out;
}

const STB_NAMES: Record<number, string> = { 0: "LOCAL", 1: "GLOBAL", 2: "WEAK", 10: "GNU_UNIQUE" };
const STT_NAMES: Record<number, string> = { 0: "NOTYPE", 1: "OBJECT", 2: "FUNC", 3: "SECTION", 4: "FILE", 5: "COMMON", 6: "TLS", 10: "GNU_IFUNC" };

function bindName(b: number) { return STB_NAMES[b] || `BIND_${b}`; }
function typeName(t: number) { return STT_NAMES[t] || `TYPE_${t}`; }

function parseGnuHash(buf: Buffer, H: any, sec: any, dynsymCount: number) {
  if (!sec) return null as any;
  const { r, is64 } = H;
  const base = sec.sh_offset;
  const nbuckets = r.u32(base + 0);
  const symndx = r.u32(base + 4);
  const maskwords = r.u32(base + 8);
  const shift2 = r.u32(base + 12);
  const wordSize = is64 ? 8 : 4;
  const bloomOff = base + 16;
  const bucketsOff = bloomOff + maskwords * wordSize;
  const chainsOff = bucketsOff + nbuckets * 4;
  let nonEmpty = 0;
  for (let i = 0; i < nbuckets; i++) {
    const b = r.u32(bucketsOff + i * 4);
    if (b !== 0) nonEmpty++;
  }
  return { nbuckets, symndx, maskwords, shift2, nonEmptyBuckets: nonEmpty };
}

function parseSysVHash(buf: Buffer, H: any, sec: any) {
  if (!sec) return null as any;
  const { r } = H;
  const base = sec.sh_offset;
  const nbucket = r.u32(base + 0);
  const nchain = r.u32(base + 4);
  let nonEmpty = 0;
  const bucketsOff = base + 8;
  for (let i = 0; i < nbucket; i++) {
    const b = r.u32(bucketsOff + i * 4);
    if (b !== 0xFFFFFFFF && b !== 0) nonEmpty++;
  }
  return { nbucket, nchain, nonEmptyBuckets: nonEmpty };
}

// ---- Anomaly sniffing ----
const SHF_EXECINSTR = 0x4;
const SHF_WRITE = 0x1;

function sniffAnomalies(H: any, shNamed: any[], dynamic: any, fileSize?: number) {
  const issues: Array<{severity: "info"|"warn"|"error"; code: string; message: string; details?: any}> = [];
  if (H.e_type !== ET_DYN) {
    issues.push({ severity: "warn", code: "ET_TYPE", message: `e_type=${H.e_type} 非ET_DYN(3)` });
  }
  const text = shNamed.find(s=>s.name===".text");
  if (text && (Number(text.sh_flags||0) & SHF_EXECINSTR) === 0) {
    issues.push({ severity: "warn", code: "TEXT_FLAGS", message: ".text 未标记可执行(SHF_EXECINSTR)" });
  }
  const data = shNamed.find(s=>s.name===".data");
  if (data && (Number(data.sh_flags||0) & SHF_WRITE) === 0) {
    issues.push({ severity: "warn", code: "DATA_NOWRITE", message: ".data 未标记可写(SHF_WRITE)" });
  }
  const rodata = shNamed.find(s=>s.name===".rodata");
  if (rodata && (Number(rodata.sh_flags||0) & SHF_WRITE) !== 0) {
    issues.push({ severity: "warn", code: "RODATA_WRITABLE", message: ".rodata 被标记为可写(SHF_WRITE)" });
  }

  // Section size anomalies
  for (const s of shNamed) {
    const size = Number(s.sh_size||0);
    const off = Number(s.sh_offset||0);
    const type = Number(s.sh_type||0);
    if (size === 0 && [".text",".dynsym",".dynstr"].includes(s.name)) {
      issues.push({ severity: "warn", code: "SEC_ZERO", message: `${s.name} 尺寸为0` });
    }
    if (fileSize && size > fileSize * 4 && type !== 8 /*SHT_NOBITS*/) {
      issues.push({ severity: "warn", code: "SEC_HUGE", message: `${s.name} 尺寸(${size}) 远大于文件(${fileSize})` });
    }
    if (fileSize && off > fileSize) {
      issues.push({ severity: "warn", code: "SEC_OFFSET_OOB", message: `${s.name} 偏移越界(off=${off} > file=${fileSize})` });
    }
    if (fileSize && off + Math.min(size, fileSize) > fileSize * 1.1 && type !== 8 /*NOBITS*/) {
      issues.push({ severity: "warn", code: "SEC_SPAN_OOB", message: `${s.name} (off+size) 超出文件范围` });
    }
  }

  if (dynamic) {
    if (typeof dynamic.runpath === "string") {
      const rp = dynamic.runpath as string;
      if (/\.\.|\s|;/.test(rp) && !rp.includes("$ORIGIN")) {
        issues.push({ severity: "warn", code: "RUNPATH_SUSPICIOUS", message: `RUNPATH 可疑: ${rp}` });
      }
    }
    if (typeof dynamic.rpath === "string") {
      const rp = dynamic.rpath as string;
      if (/\.\.|\s|;/.test(rp) && !rp.includes("$ORIGIN")) {
        issues.push({ severity: "warn", code: "RPATH_SUSPICIOUS", message: `RPATH 可疑: ${rp}` });
      }
    }
    const neededCount = (dynamic.needed?.length)||0;
    if (neededCount > 100) {
      issues.push({ severity: "info", code: "MANY_NEEDED", message: `NEEDED 依赖较多: ${neededCount}` });
    }
  }
  if (!shNamed.find(s=>s.name===".dynsym")) {
    issues.push({ severity: "warn", code: "NO_DYNSYM", message: "缺失 .dynsym" });
  }
  if (!shNamed.find(s=>s.name===".dynstr")) {
    issues.push({ severity: "warn", code: "NO_DYNSTR", message: "缺失 .dynstr" });
  }
  return issues;
}

// Suspicious imports categories
function suspiciousImports(names: string[]) {
  const mk = (arr: (string|RegExp)[], name: string) => ({ name, hits: matchAny(names, arr) });
  const cats = [
    mk([/\bptrace\b/, /\bprctl\b/, /seccomp/i], "antiDebug"),
    mk([/\bdlopen\b/, /\bdlsym\b/, /\bdladdr\b/, /\bmprotect\b/, /\bmmap\b/], "codeLoading"),
    mk([/\bsystem\b/, /\bpopen\b/, /\bexecv?e?\b/, /\bfork\b/, /\bkill\b/], "process"),
    mk([/\bsocket\b/, /\bconnect\b/, /\bsend\b/, /\brecv\b/, /inet_/i, /getaddrinfo/i], "netIO"),
    mk([/\bopen\b/, /\bfopen\b/, /\bchmod\b/, /\bchown\b/, /\bunlink\b/, /\brename\b/], "fileOps"),
    mk([/AES/i, /SHA\d*/i, /MD5/i, /EVP_/], "crypto")
  ];
  const out: Record<string, {count:number; symbols: string[]}> = {};
  for (const c of cats) if (c.hits.length) out[c.name] = { count: c.hits.length, symbols: c.hits };
  return out;
}

function matchAny(names: string[], arr: (string|RegExp)[]) {
  const hits: string[] = [];
  for (const n of names) {
    for (const p of arr) {
      if (typeof p === "string") { if (n === p) { hits.push(n); break; } }
      else { if (p.test(n)) { hits.push(n); break; } }
    }
  }
  return hits;
}

// Entry candidates
function findEntryCandidates(exports: any[], shNamed: any[]) {
  const names = exports.map(e=>e.name);
  const out: any = {};
  const pushIf = (k: string, cond: boolean, v: any) => { if (cond) { if (!out[k]) out[k] = []; out[k].push(v); } };
  pushIf("JNI", names.includes("JNI_OnLoad"), "JNI_OnLoad");
  pushIf("AndroidActivity", names.includes("ANativeActivity_onCreate"), "ANativeActivity_onCreate");
  const initArr = shNamed.find((s:any)=>s.name === ".init_array");
  if (initArr && initArr.sh_size) {
    pushIf("initArray", true, { count: Math.floor(Number(initArr.sh_size)/(Number(initArr.sh_entsize)|| (shNamed.some(s=>s.name==".text" && Number(s.sh_addr)>0) ? 8 : 4))) });
  }
  const exportedFuncs = exports.filter(e=> (e.st_type===2 || /^(Java_|JNI_On|ANative)/.test(e.name))).slice(0, 50).map((e:any)=>e.name);
  if (exportedFuncs.length) out["exportsLikelyEntry"] = exportedFuncs;
  return out;
}

export const elfAnalyzeTool: Tool = {
  name: "elf_analyze",
  description: "解析ELF(.so)：头部、Section表、Dynamic条目、导入符号（按类型/绑定聚合）、重定位统计、哈希摘要，并产出简易调用图摘要",
  schema: {
    type: "object",
    properties: {
      path: { type: "string" },
      maxSections: { type: "number", default: 200 },
      topN: { type: "number", default: 40 },
      demangle: { type: "boolean", default: true },
      filters: {
        type: "object",
        properties: {
          include: { type: "string" },
          regex: { type: "string" }
        }
      }
    },
    required: ["path"]
  },
  async handler({ path, maxSections = 200, topN = 40, demangle = true, filters }: any) {
    const buf = await fs.readFile(path);

    const H = parseHeader(buf);

    const sh = parseSectionHeaders(buf, H);
    const shNamed = attachSectionNames(buf, H, sh);

    const dynsym = findSection(shNamed, ".dynsym");
    const dynstr = findSection(shNamed, ".dynstr");
    const gnuHashSec = findSection(shNamed, ".gnu.hash");
    const sysvHashSec = findSection(shNamed, ".hash");
    const relplt = findSection(shNamed, ".rel.plt") || findSection(shNamed, ".rela.plt");
    const isRelaPlt = relplt ? (relplt.sh_type === SHT_RELA) : false;
    const reldyn = findSection(shNamed, ".rel.dyn") || findSection(shNamed, ".rela.dyn");
    const isRelaDyn = reldyn ? (reldyn.sh_type === SHT_RELA) : false;

    // Dynamic entries
    const dynamicSec = findSection(shNamed, ".dynamic");
    const dynamic: any = { needed: [] as string[] };
    if (dynamicSec) {
      const { r, is64 } = H;
      const base = dynamicSec.sh_offset;
      const entsize = dynamicSec.sh_entsize || (is64 ? 16 : 8);
      const count = Math.floor(dynamicSec.sh_size / entsize);
      // Use dynstr for resolving DT_* string offsets
      const strTab = dynstr ? buf.subarray(dynstr.sh_offset, dynstr.sh_offset + dynstr.sh_size) : null;
      for (let i = 0; i < count; i++) {
        const off = base + i * entsize;
        const d_tag = is64 ? Number(H.r.u64(off + 0)) : H.r.u32(off + 0);
        const d_val = is64 ? Number(H.r.u64(off + 8)) : H.r.u32(off + 4);
        if (d_tag === DT_NULL) break;
        if (d_tag === DT_NEEDED && strTab) dynamic.needed.push(readStr(strTab, d_val));
        else if (d_tag === DT_SONAME && strTab) dynamic.soname = readStr(strTab, d_val);
        else if (d_tag === DT_RPATH && strTab) dynamic.rpath = readStr(strTab, d_val);
        else if (d_tag === DT_RUNPATH && strTab) dynamic.runpath = readStr(strTab, d_val);
      }
    }

    // Dynsym + imports
    const dynsyms = parseDynsym(buf, H, shNamed, dynsym, dynstr);
    const imports = dynsyms.filter(s => s.st_shndx === 0 && s.name);

    // 聚合：按符号类型与绑定
    const byType = new Map<string, number>();
    const byBind = new Map<string, number>();
    for (const s of imports) {
      const t = typeName(s.st_type);
      const b = bindName(s.st_bind);
      byType.set(t, (byType.get(t) || 0) + 1);
      byBind.set(b, (byBind.get(b) || 0) + 1);
    }
    const funcSample = imports.filter(s => s.st_type === 2).slice(0, topN).map(s => s.name);

    // Relocations and symbol hot spots
    const relPltEntries = parseRelocs(buf, H, relplt, isRelaPlt);
    const relDynEntries = parseRelocs(buf, H, reldyn, isRelaDyn);

    const nameByIndex = (idx: number) => (dynsyms[idx]?.name || "");
    const inc = (m: Map<string, number>, k: string) => { if (!k) return; m.set(k, (m.get(k) || 0) + 1); };

    const cntPlt = new Map<string, number>();
    for (const r of relPltEntries) inc(cntPlt, nameByIndex(r.r_sym));
    const cntDyn = new Map<string, number>();
    for (const r of relDynEntries) inc(cntDyn, nameByIndex(r.r_sym));

    const topFromMap = (m: Map<string, number>) => Array.from(m.entries()).sort((a,b)=>b[1]-a[1]).slice(0, topN).map(([name,count])=>({name,count}));

    const sectionsOut = shNamed.slice(0, maxSections).map(s => ({
      name: s.name,
      type: s.sh_type,
      addr: toHex(Number(s.sh_addr || 0)),
      off: toHex(Number(s.sh_offset || 0)),
      size: s.sh_size,
      flags: Number(s.sh_flags ?? 0)
    }));

    const summary = {
      class: H.is64 ? "ELF64" : "ELF32",
      endian: H.little ? "LE" : "BE",
      machine: EM_NAMES[H.e_machine] || `EM_${H.e_machine}`,
      entry: toHex(H.e_entry),
      phnum: H.e_phnum,
      shnum: H.e_shnum,
      imports: imports.length,
      neededLibs: dynamic.needed?.length || 0,
      pltRelocs: relPltEntries.length,
      dynRelocs: relDynEntries.length
    };

    const gnuHash = parseGnuHash(buf, H, gnuHashSec, dynsyms.length);
    const sysvHash = parseSysVHash(buf, H, sysvHashSec);

    const callGraphSummary = {
      importHotspots: topFromMap(cntPlt),
      relocationHotspots: topFromMap(cntDyn)
    };

    // Optional demangling
    let demap = new Map<string, string>();
    if (demangle) {
      const { demangleMany } = await import("../utils/demangle.js");
      const toDm: string[] = [];
      toDm.push(...imports.slice(0, topN).map(s=>s.name));
      for (const e of callGraphSummary.importHotspots) toDm.push(e.name);
      for (const e of callGraphSummary.relocationHotspots) toDm.push(e.name);
      for (const e of (relPltEntries||[])) { const nm = nameByIndex(e.r_sym); if (nm) toDm.push(nm); }
      for (const e of (relDynEntries||[])) { const nm = nameByIndex(e.r_sym); if (nm) toDm.push(nm); }
      demap = await demangleMany(toDm);
    }

    // Filters
    let predicate: ((s: string) => boolean) | null = null;
    if (filters?.include) predicate = (s) => s.includes(filters.include);
    else if (filters?.regex) {
      try { const re = new RegExp(filters.regex, "i"); predicate = (s)=>re.test(s); } catch {}
    }
    const matched = predicate ? {
      imports: imports.filter(s=>predicate!(s.name)).map(s=>s.name),
      plt: relPltEntries.map(e=>nameByIndex(e.r_sym)).filter(Boolean).filter(predicate!),
      dyn: relDynEntries.map(e=>nameByIndex(e.r_sym)).filter(Boolean).filter(predicate!)
    } : undefined;

    const decorateSymList = (list: {name:string,count:number}[]) => list.map(e=>({ ...e, demangledName: demap.get(e.name) || e.name }));

    // Suspicious imports clustering
    const suspicious = suspiciousImports(imports.map(s=>s.name));

    // Possible entry clusters
    const exportedSyms = dynsyms.filter(s=> s.st_shndx !== 0 && s.name);
    const entryCandidates = findEntryCandidates(exportedSyms, shNamed);

    const result = {
      header: summary,
      sections: sectionsOut,
      dynamic,
      imports: {
        count: imports.length,
        sample: imports.slice(0, topN).map(s => s.name),
        sampleDemangled: imports.slice(0, topN).map(s => demap.get(s.name) || s.name),
        byType: Array.from(byType.entries()).map(([k,v])=>({type:k,count:v})),
        byBind: Array.from(byBind.entries()).map(([k,v])=>({bind:k,count:v})),
        funcSample,
        funcSampleDemangled: funcSample.map(n=> demap.get(n) || n)
      },
      relocations: {
        pltCount: relPltEntries.length,
        dynCount: relDynEntries.length,
        topPltSymbols: topFromMap(cntPlt),
        topPltSymbolsDemangled: decorateSymList(topFromMap(cntPlt)),
        topDynSymbols: topFromMap(cntDyn),
        topDynSymbolsDemangled: decorateSymList(topFromMap(cntDyn))
      },
      callGraphSummary: {
        importHotspots: callGraphSummary.importHotspots,
        importHotspotsDemangled: decorateSymList(callGraphSummary.importHotspots),
        relocationHotspots: callGraphSummary.relocationHotspots,
        relocationHotspotsDemangled: decorateSymList(callGraphSummary.relocationHotspots)
      },
      hashes: { gnuHash, sysvHash },
      matches: matched,
      anomalies: sniffAnomalies(H, shNamed, dynamic, buf.length),
      suspiciousImports: suspicious,
      entryCandidates
    } as any;

    // Markdown render
    try {
      const { renderElfMarkdown } = await import("../utils/render.js");
      (result as any).render = { markdown: renderElfMarkdown(result) };
    } catch {}

    return result;
  }
};
