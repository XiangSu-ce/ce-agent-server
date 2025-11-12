import { createHash } from "crypto";

export type FilterConfig = {
  blocklist: string[];                    // 词表（将转为耐污点正则）
  allowlist: string[];                    // 全局放行词
  replacements: Record<string, string>;   // 命中词→替代
};

export type PagePolicy = {
  pageId: string;
  allowlist: string[];
};

export type FilterPack = {
  base: FilterConfig;
  pages: PagePolicy[];
};

const ZERO_WIDTH = /[\u200B-\u200F\uFEFF]/g;

function normalize(s: string) {
  return s.normalize("NFKC").replace(ZERO_WIDTH, "");
}

function escapeRe(s: string) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// 允许字符间穿插少量符号/空白，提升鲁棒性
function fuzzyPattern(term: string) {
  const chars = [...term];
  return chars.map(c => {
    const e = escapeRe(c);
    return `${e}(?:[\n\r\s_\-|·\.]{0,2})`;
  }).join("");
}

function buildUnionRegex(terms: string[]) {
  const p = terms
    .filter(Boolean)
    .map(t => fuzzyPattern(t))
    .join("|");
  return p ? new RegExp(`(?:${p})`, "ig") : null;
}

function buildAllowRegex(terms: string[]) {
  const p = terms
    .filter(Boolean)
    .map(t => fuzzyPattern(t))
    .join("|");
  return p ? new RegExp(`(?:${p})`, "i") : null;
}

export function applyFilter(text: string, pack: FilterPack, pageId?: string) {
  const raw = normalize(text);
  const page = pack.pages.find(p => p.pageId === pageId);
  const allowTerms = new Set([
    ...pack.base.allowlist.map(normalize),
    ...(page?.allowlist ?? []).map(normalize),
  ]);

  const allowRe = buildAllowRegex([...allowTerms]);
  const blockRe = buildUnionRegex(pack.base.blocklist.map(normalize));

  if (!blockRe) return { action: "pass" as const, output: raw, hits: [] as string[] };

  const hits = new Set<string>();
  let out = raw.replace(blockRe, (m: string) => {
    // 若被 allowlist 覆盖，直接放行
    if (allowRe && allowRe.test(m)) return m;

    // 精确替换：优先找原始词的替代
    const kv = Object.entries(pack.base.replacements).find(([k]) => {
      const re = new RegExp(fuzzyPattern(normalize(k)), "i");
      return re.test(m);
    });
    hits.add(m);
    return kv ? kv[1] : "【已替换】";
  });

  if (hits.size === 0) return { action: "pass" as const, output: raw, hits: [] as string[] };
  return { action: "rewrite" as const, output: out, hits: [...hits] };
}

export function hashForAudit(s: string) {
  return createHash("sha256").update(s).digest("hex").slice(0, 16);
}
