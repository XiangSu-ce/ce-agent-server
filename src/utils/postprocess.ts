export function compressRuns(s: string, maxRepeats = 3) {
  return s.replace(/(.)\1{5,}/g, (_m, ch) => ch.repeat(maxRepeats));
}

export function collapseDuplicateLines(s: string) {
  const lines = s.split(/\r?\n/);
  const out: string[] = [];
  let prev = "";
  for (const ln of lines) {
    if (ln.trim() === prev.trim()) continue;
    out.push(ln);
    prev = ln;
  }
  return out.join("\n");
}

export function postProcessText(s: string) {
  return collapseDuplicateLines(compressRuns(s));
}
