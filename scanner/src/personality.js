// Security personality voices (v0.74).
//
// Same findings, dramatically different shareability. Three modes:
//
//   - sage      (default): calm explainer. "Consider that..." Reasonable
//                tone for compliance audiences + general engineering.
//   - cassandra: alarmist. "This WILL ship as a CVE." Sells urgency to
//                management; useful for getting buy-in on remediation
//                budget.
//   - vince:    drill-sergeant. "Ship this and you're paged at 3am."
//                Sells discipline; popular with vets / staff engineers
//                who want zero ceremony.
//
// Selection: AGENTIC_SECURITY_PERSONALITY env var, or `personality:`
// field on the renderer call. Defaults to 'sage'.
//
// What's actually different per voice:
//   1. The OPENING line of any rendered report
//   2. The PHRASING of severity descriptors
//   3. The CLOSING line / call-to-action
//   4. Specific lexical choices (emoji density, hedging vs. assertive,
//      ALL CAPS for emphasis)
//
// What's THE SAME across voices:
//   - The technical content (CWEs, finding IDs, file:line, remediation)
//   - Severity assignments (a critical is a critical regardless of voice)
//   - Counts + summary statistics
//   - The decision (blocking-merge or non-blocking)
//
// Operators changing voice does NOT change WHAT findings fire — only
// how they read.

const VOICES = {
  sage: {
    glyph: '🛡',
    openingClean: (n) => n === 0
      ? `No security delta. Safe to merge.`
      : `Clean scan — ${n} pre-existing findings unchanged.`,
    openingNeedsWork: (n, files) =>
      `I looked at the ${files} file${files === 1 ? '' : 's'} you changed and noticed ${n} new finding${n === 1 ? '' : 's'} worth your attention.`,
    severityWord: (s) => ({
      critical: 'critical',
      high: 'high-severity',
      medium: 'medium-severity',
      low: 'low-impact',
      info: 'informational',
    }[s] || s),
    closingBlocking: (counts) =>
      `**Blocking merge:** ${counts.critical} critical + ${counts.high} high. Address these before merging — happy to walk through any of them.`,
    closingNonblocking: () =>
      `Non-blocking, but worth fixing while context is fresh.`,
    fixCue: 'Suggested fix',
  },
  cassandra: {
    glyph: '🚨',
    openingClean: (n) => n === 0
      ? `No new vulnerabilities introduced. The existing surface is still attackable, but you didn't make it worse.`
      : `Scan is "clean" — but you're sitting on ${n} pre-existing findings. Today is the day they get exploited.`,
    openingNeedsWork: (n, files) =>
      `**${n} new attack surface${n === 1 ? '' : 's'}** opened in ${files} file${files === 1 ? '' : 's'}. This is how breaches start.`,
    severityWord: (s) => ({
      critical: 'CRITICAL — RCE-class',
      high: 'high — exploitable today',
      medium: 'medium — exploitable with chaining',
      low: 'low — exploitable in 18 months when the toolchain catches up',
      info: 'informational — write it down anyway',
    }[s] || s),
    closingBlocking: (counts) =>
      `🚨 **DO NOT MERGE.** ${counts.critical} CRITICAL + ${counts.high} HIGH severity. Each one is a CVE waiting for a researcher. Fix or revert.`,
    closingNonblocking: () =>
      `No criticals — yet. Fix the rest before they chain into something that matters.`,
    fixCue: 'Mitigation (apply now)',
  },
  vince: {
    glyph: '🪖',
    openingClean: (n) => n === 0
      ? `Clean. Move out.`
      : `Nothing new added. ${n} legacy findings still on the board — that's tomorrow's problem.`,
    openingNeedsWork: (n, files) =>
      `${n} new finding${n === 1 ? '' : 's'} in ${files} file${files === 1 ? '' : 's'}. Drop and give me twenty fixes.`,
    severityWord: (s) => ({
      critical: 'CRITICAL',
      high: 'HIGH',
      medium: 'MEDIUM',
      low: 'LOW',
      info: 'INFO',
    }[s] || s.toUpperCase()),
    closingBlocking: (counts) =>
      `**HALT.** ${counts.critical} critical, ${counts.high} high. Ship this and you're paged at 3am. Fix it before the standup.`,
    closingNonblocking: () =>
      `No critical or high. You're cleared to merge — but address the rest this sprint. No exceptions, no carryover.`,
    fixCue: 'Fix',
  },
};

export function getPersonality(name) {
  const key = String(name || process.env.AGENTIC_SECURITY_PERSONALITY || 'sage').toLowerCase();
  return VOICES[key] || VOICES.sage;
}

export function listPersonalities() { return Object.keys(VOICES); }

/**
 * Wrap a renderer output's opening / closing lines with the active
 * personality. Caller passes the raw delta + the personality name (or
 * uses env default).
 *
 * This is intentionally additive — the renderer's middle body (CWE
 * 'why' paragraphs, per-finding lines) is identical across voices.
 * Only the framing changes.
 */
export function applyPersonality(rendered, delta, personality) {
  const voice = getPersonality(personality);
  if (!rendered || !delta) return rendered;
  const intro = (delta.introduced || []).length;
  const resolved = (delta.resolved || []).length;
  const shifted = (delta.shifted || []).length;
  const filesN = (delta.changedFiles || []).length;
  // Replace the existing first-paragraph greeting with the voice-specific one.
  let opening;
  if (intro === 0 && resolved === 0 && shifted === 0) {
    opening = voice.openingClean(delta.head?.summary?.total || 0);
  } else if (intro === 0) {
    opening = voice.openingClean(delta.head?.summary?.total || 0);
  } else {
    opening = voice.openingNeedsWork(intro, filesN);
  }
  // Replace closing/footer based on blocking status.
  const i = delta.summary?.introduced || {};
  const blocking = (i.critical || 0) + (i.high || 0) > 0;
  const closing = blocking
    ? voice.closingBlocking({ critical: i.critical || 0, high: i.high || 0 })
    : voice.closingNonblocking();
  // The rendered output has a structure: heading line, blank, opening,
  // ..., separator line ('---'), blocking-or-nonblocking footer.
  const lines = rendered.split('\n');
  // Find the first non-empty content line after the heading.
  let openingLineIdx = -1;
  for (let i = 0; i < lines.length; i++) {
    if (i > 0 && lines[i].trim() && !lines[i].startsWith('###')) {
      openingLineIdx = i;
      break;
    }
  }
  if (openingLineIdx > 0) lines[openingLineIdx] = opening;
  // Replace the heading glyph.
  if (lines[0]) {
    lines[0] = lines[0].replace(/^###\s+🛡/, `### ${voice.glyph}`);
  }
  // Replace the closing line (last non-empty line after the '---' separator).
  let separatorIdx = -1;
  for (let i = lines.length - 1; i >= 0; i--) {
    if (lines[i].trim() === '---') { separatorIdx = i; break; }
  }
  if (separatorIdx > 0) {
    // Find the first non-empty line after the separator and replace it.
    for (let i = separatorIdx + 1; i < lines.length; i++) {
      if (lines[i].trim()) { lines[i] = closing; break; }
    }
  }
  return lines.join('\n');
}

export const _internal = { VOICES };
