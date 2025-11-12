export function renderElfMarkdown(r: any): string {
  if (r?.error) {
    return [
      `# ELF 分析报告`,
      ``,
      `状态: ${r.error}`,
      r.detectedFormat ? `检测格式: ${r.detectedFormat}` : "",
      r.advice ? `建议: ${r.advice}` : (r.message||"")
    ].filter(Boolean).join("\n");
  }
  const lines: string[] = [];
  const header = r.header || {};
  lines.push(`# ELF 分析报告`);
  lines.push("");
  lines.push(`## 概览`);
  lines.push(`- 类别: ${header.class}`);
  lines.push(`- 字节序: ${header.endian}`);
  lines.push(`- 架构: ${header.machine}`);
  lines.push(`- 入口: ${header.entry}`);
  lines.push(`- 节数量: ${header.shnum} | 程序段: ${header.phnum}`);
  lines.push(`- 依赖库: ${header.neededLibs} | 导入符号: ${header.imports}`);
  lines.push(`- 重定位: PLT=${header.pltRelocs} / DYN=${header.dynRelocs}`);
  lines.push("");

  if (r.dynamic?.needed?.length) {
    lines.push(`## 依赖库 (NEEDED)`);
    for (const n of r.dynamic.needed) lines.push(`- ${n}`);
    lines.push("");
  }

  if (Array.isArray(r.sections)) {
    lines.push(`## 重要节 (Top ${Math.min(20, r.sections.length)})`);
    lines.push(`| 名称 | 类型 | 地址 | 偏移 | 大小 | 标志 |`);
    lines.push(`|---|---:|---:|---:|---:|---:|`);
    for (const s of r.sections.slice(0, 20)) {
      lines.push(`| ${s.name} | ${s.type} | ${s.addr} | ${s.off} | ${s.size} | ${s.flags ?? ""} |`);
    }
    lines.push("");
  }

  if (r.imports) {
    lines.push(`## 导入统计`);
    lines.push(`- 总数: ${r.imports.count}`);
    if (r.imports.byType?.length) {
      lines.push(`- 按类型:`);
      for (const it of r.imports.byType) lines.push(`  - ${it.type}: ${it.count}`);
    }
    if (r.imports.byBind?.length) {
      lines.push(`- 按绑定:`);
      for (const ib of r.imports.byBind) lines.push(`  - ${ib.bind}: ${ib.count}`);
    }
    if (r.imports.sampleDemangled?.length) {
      lines.push(`- 示例(解符号):`);
      for (const n of r.imports.sampleDemangled.slice(0, 20)) lines.push(`  - ${n}`);
    }
    lines.push("");
  }

  if (r.suspiciousImports && Object.keys(r.suspiciousImports).length) {
    lines.push(`## 可疑导入分类`);
    for (const [cat, val] of Object.entries(r.suspiciousImports)) {
      lines.push(`- ${cat} (${(val as any).count})`);
      for (const n of (val as any).symbols.slice(0, 30)) lines.push(`  - ${n}`);
    }
    lines.push("");
  }

  if (r.relocations) {
    lines.push(`## 重定位热点`);
    const showHot = (title: string, list: any[]) => {
      if (!list?.length) return;
      lines.push(`- ${title}`);
      for (const e of list.slice(0, 20)) lines.push(`  - ${e.demangledName || e.name}: ${e.count}`);
    };
    showHot("PLT", r.relocations.topPltSymbolsDemangled || r.relocations.topPltSymbols);
    showHot("DYN", r.relocations.topDynSymbolsDemangled || r.relocations.topDynSymbols);
    lines.push("");
  }

  if (r.entryCandidates && Object.keys(r.entryCandidates).length) {
    lines.push(`## 可能入口/初始化`);
    for (const [k, v] of Object.entries(r.entryCandidates)) {
      lines.push(`- ${k}`);
      if (Array.isArray(v)) for (const it of v.slice(0, 20)) lines.push(`  - ${typeof it === "string" ? it : JSON.stringify(it)}`);
    }
    lines.push("");
  }

  if (r.hashes) {
    lines.push(`## 符号哈希摘要`);
    if (r.hashes.gnuHash) lines.push(`- GNU Hash: buckets=${r.hashes.gnuHash.nbuckets}, nonEmpty=${r.hashes.gnuHash.nonEmptyBuckets}, symndx=${r.hashes.gnuHash.symndx}`);
    if (r.hashes.sysvHash) lines.push(`- SysV Hash: nbucket=${r.hashes.sysvHash.nbucket}, nonEmpty=${r.hashes.sysvHash.nonEmptyBuckets}`);
    lines.push("");
  }

  if (r.anomalies?.length) {
    lines.push(`## 异常嗅探`);
    for (const a of r.anomalies) {
      lines.push(`- [${a.severity}] ${a.code}: ${a.message}`);
    }
    lines.push("");
  }

  return lines.join("\n");
}
