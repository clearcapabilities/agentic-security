import { isChainWorthy, familyForBoundary } from './cross-lang-meta.js';

// SQL / ORM round-trip taint (Sentinel-parity FR-DET-3).
//
// When a tainted value is written to column C of table T via an ORM `create`
// or `update`, subsequent reads of T.C are tainted — the database is just a
// persistence layer, not a sanitizer. This module builds a table.column→
// tainted-source registry and emits chains.
//
// Coverage:
//   - JS/TS: Mongoose (.create / .save / .findOne), Sequelize, Prisma
//   - Python: SQLAlchemy session.add, Django ORM .objects.create / .filter
//   - Ruby: ActiveRecord Model.create / Model.where
//   - Go:   GORM .Create / .Where
//   - PHP:  Eloquent ::create / ::where
//
// The detector is necessarily heuristic; we name table+column by best-effort.

const TAINT_HINTS = /\b(req|request|ctx\.request|params|input|userInput|body|query|cookies|headers)\b/;

// Identify ORM writes that bind a literal field name to a tainted value.
// Returns [{file, line, model, field, taintHint}].
function findOrmWrites(fileContents) {
  const out = [];
  for (const [fp, c] of Object.entries(fileContents || {})) {
    if (!c || typeof c !== 'string') continue;
    if (c.length > 500_000) continue;
    const lang = (fp.match(/\.([a-z]+)$/i) || [])[1] || '';
    if (!/^(?:js|jsx|ts|tsx|mjs|cjs|py|rb|go|php)$/i.test(lang)) continue;

    // Match patterns like  Model.create({ <field>: <expr-with-taint> })
    // or  await Model.create({ data: { <field>: <expr> } })  (Prisma)
    const reJsPyRb = /\b([A-Z]\w+)\s*\.\s*(?:create|save|update|build|insert|upsert)\s*\(\s*\{([^}]{0,500})\}/g;
    let m;
    while ((m = reJsPyRb.exec(c))) {
      const model = m[1];
      const body = m[2];
      // Prisma wraps under `data: { ... }`
      const prismaInner = body.match(/data\s*:\s*\{([^}]{0,400})\}/);
      const fields = prismaInner ? prismaInner[1] : body;
      const fieldRe = /\b(\w+)\s*:\s*([^,}\n]+)/g;
      let fm;
      while ((fm = fieldRe.exec(fields))) {
        const field = fm[1];
        const val = fm[2].trim();
        if (TAINT_HINTS.test(val)) {
          const line = c.substring(0, m.index).split('\n').length;
          out.push({ file: fp, line, model, field, val: val.slice(0, 60) });
        }
      }
    }
    // Python kwargs:  Model.objects.create(field1=value, field2=value)
    const rePyKw = /\b([A-Z]\w+)\.objects\.create\s*\(([^)]{0,500})\)/g;
    while ((m = rePyKw.exec(c))) {
      const model = m[1];
      const body = m[2];
      const kwRe = /\b(\w+)\s*=\s*([^,)]+)/g;
      let km;
      while ((km = kwRe.exec(body))) {
        const field = km[1];
        const val = km[2].trim();
        if (TAINT_HINTS.test(val)) {
          const line = c.substring(0, m.index).split('\n').length;
          out.push({ file: fp, line, model, field, val: val.slice(0, 60) });
        }
      }
    }
    // GORM:  db.Create(&user)  or  db.Model(&User{}).Where(...).Update("col", val)
    const reGormUpdate = /db\s*\.\s*(?:Model\([^)]*\)\s*\.\s*)?(?:Where[^.]*\.\s*)?Update\s*\(\s*"(\w+)"\s*,\s*([^)]+)\)/g;
    while ((m = reGormUpdate.exec(c))) {
      const field = m[1];
      const val = m[2].trim();
      if (TAINT_HINTS.test(val)) {
        const line = c.substring(0, m.index).split('\n').length;
        out.push({ file: fp, line, model: '<gorm>', field, val: val.slice(0, 60) });
      }
    }
  }
  return out;
}

// Find ORM reads — any Model.findX / Model.where / Model.filter / db.Query / etc.
// that READS column C and BINDS its value into a downstream use.
// Returns [{file, line, model, field}] candidate read sites.
function findOrmReads(fileContents) {
  const out = [];
  for (const [fp, c] of Object.entries(fileContents || {})) {
    if (!c || typeof c !== 'string') continue;
    if (c.length > 500_000) continue;
    // Match Model.findX(...) / Model.objects.filter(...) / Model.where(...)
    const reRead = /\b([A-Z]\w+)\s*\.\s*(?:findOne|findAll|findBy\w*|find|findById|first|last|where|filter|objects\.get|objects\.filter|objects\.all)\s*\(/g;
    let m;
    while ((m = reRead.exec(c))) {
      const model = m[1];
      const line = c.substring(0, m.index).split('\n').length;
      out.push({ file: fp, line, model });
    }
  }
  return out;
}

export function scanCrossLangOrm(fileContents, existingFindings) {
  const writes = findOrmWrites(fileContents);
  if (writes.length === 0) return [];
  const reads = findOrmReads(fileContents);
  if (reads.length === 0) return [];

  // Index sinks: collect sink lines + their snippets from existing findings.
  const sinksByFile = new Map();
  for (const f of existingFindings || []) {
    const sink = f.sink || f;
    const file = sink.file || f.file;
    const line = sink.line || f.line;
    if (!file || !line) continue;
    if (!/critical|high|medium/i.test(f.severity || '')) continue;
    if (!isChainWorthy(f)) continue;   // FR-CHAIN-FILTER
    if (!sinksByFile.has(file)) sinksByFile.set(file, []);
    sinksByFile.get(file).push({ line, vuln: f.vuln, severity: f.severity });
  }

  const out = [];
  for (const w of writes) {
    // Find any READ of the same Model — anywhere in the project.
    const readers = reads.filter(r => r.model === w.model);
    if (!readers.length) continue;
    for (const r of readers) {
      // Check if there's a sink in the reader's file near the read line.
      const sinksInReadFile = sinksByFile.get(r.file) || [];
      const nearby = sinksInReadFile.filter(s => Math.abs((s.line || 0) - r.line) <= 20);
      if (!nearby.length) continue;
      const seed = nearby[0];
      out.push({
        id: `xlang-orm:${w.file}:${w.line}->${r.file}:${r.line}`,
        file: r.file, line: r.line,
        vuln: `Cross-Language Taint (ORM round-trip): ${w.model}.${w.field} written tainted at ${w.file}:${w.line} → read at ${r.file}:${r.line} → reaches ${seed.severity} sink`,
        severity: 'medium',
        cwe: 'CWE-89',
        snippet: `(round-trip via ${w.model}.${w.field})`,
        remediation: `A tainted value is written to ${w.model}.${w.field} at ${w.file}:${w.line} and read at ${r.file}:${r.line}, then flows into "${seed.vuln}". The DB doesn't sanitize — coerce/validate the value on write OR on read, ideally both. For Mongo, ensure the value is a primitive (String(...)) before write; for SQL, parameterize the downstream sink.`,
        parser: 'XLANG-ORM',
        family: familyForBoundary('orm'),   // FR-FAMILY-REGISTRY
        confidence: 0.55,
        cross_language: true,
        chain: [
          { file: w.file, line: w.line, label: `write ${w.model}.${w.field}` },
          { file: r.file, line: r.line, label: `read ${w.model}` },
          { file: r.file, line: seed.line, label: seed.vuln },
        ],
      });
    }
  }
  return out;
}
