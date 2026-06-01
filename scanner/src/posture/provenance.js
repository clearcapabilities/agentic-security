// R17 (PRD §5) — finding provenance: "one issue, many signals".
//
// dedupeFindingsWithEvidence() already collapses findings that share a
// (file, sink-line, family) into ONE finding and accumulates the parsers that
// fired into `evidence`. This annotator turns that into an explicit, queryable
// corroboration signal on EVERY finding (not just merged ones):
//
//   finding.corroborationCount : number of DISTINCT independent analyses that
//                                flagged this exact issue (≥1).
//   finding.corroboration.by   : sorted list of those signal sources.
//   finding.multiSignal        : true when ≥2 independent sources agree.
//
// Independent confirmation lowers the odds of a false positive, so the engine
// ranks multi-signal findings above single-signal ones at equal severity. It
// deliberately does NOT touch the calibrated `confidence` field — calibration
// is fit/measured held-out (see posture/CLAUDE.md) and must not be perturbed by
// a ranking heuristic.

export function annotateFindingProvenance(findings) {
  if (!Array.isArray(findings)) return findings;
  for (const f of findings) {
    if (!f || typeof f !== 'object') continue;
    const sources = new Set();
    if (f.parser) sources.add(f.parser);
    // Parsers merged in by the dedup pass.
    if (Array.isArray(f.evidence)) for (const e of f.evidence) if (e) sources.add(e);
    // The Layer-3 LLM validator accepting a finding is an independent signal.
    if (f.validator_verdict === 'accept') sources.add('llm-validator');
    // A dynamically-confirmed finding (reserved for the DAST loop) is the
    // strongest independent signal.
    if (f.dynamicallyConfirmed === true) sources.add('dynamic');
    if (sources.size === 0) sources.add(f.parser || 'UNKNOWN');
    const by = [...sources].sort();
    f.corroboration = { count: by.length, by };
    f.corroborationCount = by.length;
    if (by.length >= 2) f.multiSignal = true;
  }
  return findings;
}
