// Corpus coverage / gap reporter (roadmap #10).
//
// "Scale the ground-truth corpus" is a data-acquisition effort, not a code one
// — but you can't prioritize what you can't see. This turns the CVE-replay
// corpus into an actionable coverage map: progress toward the target size, and
// exactly which CWE×language cells have zero ground-truth entries. It measures
// the existing corpus only; it never invents entries.

// The corpus's declared target families/languages (mirrors bench manifest).
export const TARGET_CWES = [
  'CWE-22', 'CWE-78', 'CWE-79', 'CWE-89', 'CWE-90', 'CWE-94', 'CWE-113',
  'CWE-327', 'CWE-329', 'CWE-338', 'CWE-352', 'CWE-502', 'CWE-601', 'CWE-611',
  'CWE-643', 'CWE-798', 'CWE-916', 'CWE-918', 'CWE-1321', 'CWE-1333',
];
export const TARGET_LANGUAGES = [
  'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'kotlin',
];

// Pure analyzer. `entries` = [{ cwe, language, family, cve, tier? }, …].
export function analyzeCorpus(entries, opts = {}) {
  const target = opts.target || 500;
  const cwes = opts.cweFamilies || TARGET_CWES;
  const langs = opts.languages || TARGET_LANGUAGES;
  const list = Array.isArray(entries) ? entries : [];

  const byLanguage = {}, byCwe = {}, matrix = {};
  for (const e of list) {
    const lang = (e && e.language) || 'unknown';
    const cwe = (e && e.cwe) || 'unknown';
    byLanguage[lang] = (byLanguage[lang] || 0) + 1;
    byCwe[cwe] = (byCwe[cwe] || 0) + 1;
    (matrix[cwe] || (matrix[cwe] = {}))[lang] = (matrix[cwe][lang] || 0) + 1;
  }

  // Empty cells in the target CWE×language matrix = prioritized gaps.
  const gaps = [];
  for (const cwe of cwes) {
    for (const lang of langs) {
      if (!(matrix[cwe] && matrix[cwe][lang])) gaps.push({ cwe, language: lang });
    }
  }
  const cellsTotal = cwes.length * langs.length;
  return {
    total: list.length,
    target,
    progressPct: Math.round((list.length / target) * 100),
    remainingToTarget: Math.max(0, target - list.length),
    byLanguage,
    byCwe,
    matrix,
    cellsTotal,
    cellsCovered: cellsTotal - gaps.length,
    gapCount: gaps.length,
    gaps,
  };
}

export function summarizeCorpusStatus(r) {
  if (!r) return 'corpus: (no data)';
  const lines = [
    `corpus: ${r.total}/${r.target} entries (${r.progressPct}%, ${r.remainingToTarget} to target)`,
    `matrix: ${r.cellsCovered}/${r.cellsTotal} CWE×language cells covered (${r.gapCount} gaps)`,
  ];
  // Top under-covered languages (fewest entries among target languages).
  const langCounts = Object.entries(r.byLanguage).sort((a, b) => a[1] - b[1]);
  if (langCounts.length) {
    lines.push('thinnest languages: ' + langCounts.slice(0, 3).map(([l, n]) => `${l}=${n}`).join(', '));
  }
  // A few example gaps to act on first.
  if (r.gaps.length) {
    lines.push('example gaps: ' + r.gaps.slice(0, 6).map(g => `${g.cwe}/${g.language}`).join(', '));
  }
  return lines.join('\n');
}
