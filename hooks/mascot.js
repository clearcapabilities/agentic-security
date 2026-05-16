'use strict';
//
// Patch — terminal-rendered mascot for agentic-security.
//
// Mirrors the lockup + ALERT + APPROVE expressions from
// docs/brand/patch-mascot.html, adapted to a monospace terminal:
// box-drawing eye bumps + body, single mouth glyph that switches with state.
//
// Palette taken from the design canon:
//   FROG  #FF6B2C  Pumilio Orange       (body, eye bumps)
//   DEEP  #C93414  Toxin Red            (freckles, alert mouth)
//   CREAM #F4EFE6  Bone                 (wordmark body copy)
//
// NO_COLOR or non-TTY stderr collapses to plain box drawing.
//
const fs = require('fs');
const path = require('path');

const useColor = !!process.stderr.isTTY && !process.env.NO_COLOR;
const C = useColor ? {
  FROG:  '\x1b[38;2;255;107;44m',
  DEEP:  '\x1b[38;2;201;52;20m',
  CREAM: '\x1b[38;2;244;239;230m',
  DIM:   '\x1b[2m',
  BOLD:  '\x1b[1m',
  RESET: '\x1b[0m',
} : { FROG: '', DEEP: '', CREAM: '', DIM: '', BOLD: '', RESET: '' };

function pluginVersion() {
  try {
    const root = process.env.CLAUDE_PLUGIN_ROOT || path.resolve(__dirname, '..');
    const pkg = JSON.parse(fs.readFileSync(path.join(root, '.claude-plugin', 'plugin.json'), 'utf8'));
    return pkg.version || '';
  } catch { return ''; }
}

// Lockup 01 from the design — dark/horizontal: bug-scene mark + wordmark.
// Terminal version compresses the bug-scene to a side-eye frog (eye bumps,
// freckles, smirk) and sets "agentic-security" beside it in bold.
function lockup() {
  const { FROG, DEEP, CREAM, DIM, BOLD, RESET } = C;
  const v = pluginVersion();
  const vSuffix = v ? ` ${DIM}· v${v}${RESET}` : '';
  return [
    '',
    `       ${FROG}╭───╮ ╭───╮${RESET}`,
    `       ${FROG}│ ${BOLD}◉${RESET}${FROG} │ │ ${BOLD}◉${RESET}${FROG} │${RESET}        ${BOLD}agentic-security${RESET}`,
    `       ${FROG}╰─┬─╯ ╰─┬─╯${RESET}        ${DIM}─────────────────${RESET}`,
    `      ${FROG}╭──┴─────┴──╮${RESET}       ${CREAM}Tiny. ${FROG}${BOLD}Bright.${RESET}${CREAM} Watching.${RESET}`,
    `      ${FROG}│  ${DEEP}·${FROG}  ${BOLD}⌣${RESET}${FROG}  ${DEEP}·${FROG}  │${RESET}       ${DIM}Built by Clear Capabilities${RESET}${vSuffix}`,
    `      ${FROG}╰───────────╯${RESET}`,
    '',
  ].join('\n');
}

// Expression 02 — ALERT · finding detected.
// Dilated wide pupils (⊙) + small "O" mouth (◯) below.
function alertFace() {
  const { FROG, DEEP, BOLD, RESET } = C;
  return [
    `   ${FROG}╭───╮ ╭───╮${RESET}`,
    `   ${FROG}│ ${BOLD}⊙${RESET}${FROG} │ │ ${BOLD}⊙${RESET}${FROG} │${RESET}`,
    `   ${FROG}╰───╯ ╰───╯${RESET}`,
    `       ${DEEP}${BOLD}◯${RESET}`,
  ].join('\n');
}

// Expression 05 — APPROVE · safe to deploy.
// Happy closed (‿) eyes + smile glyph below.
function approveFace() {
  const { FROG, BOLD, RESET } = C;
  return [
    `   ${FROG}╭───╮ ╭───╮${RESET}`,
    `   ${FROG}│ ${BOLD}‿${RESET}${FROG} │ │ ${BOLD}‿${RESET}${FROG} │${RESET}`,
    `   ${FROG}╰───╯ ╰───╯${RESET}`,
    `      ${BOLD}‿‿${RESET}`,
  ].join('\n');
}

module.exports = { lockup, alertFace, approveFace };
