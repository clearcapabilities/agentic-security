// Patch — terminal mascot expressions for the ship-verdict renderer.
//
// Mirrors the ALERT (02) and APPROVE (05) expressions from
// docs/brand/patch-mascot.html, scaled down to a four-line monospace face.
// The caller passes `color` (the same flag toShipVerdict already gates on);
// NO_COLOR additionally forces a plain render.
//
// Kept self-contained so the bundled scanner has no extra import surface.

const ON = {
  FROG:  '\x1b[38;2;255;107;44m',
  DEEP:  '\x1b[38;2;201;52;20m',
  BOLD:  '\x1b[1m',
  RESET: '\x1b[0m',
};
const OFF = { FROG: '', DEEP: '', BOLD: '', RESET: '' };

function paint(enabled) {
  return (enabled === false || process.env.NO_COLOR) ? OFF : ON;
}

// Dilated wide pupils + small "O" mouth: scanner caught something.
export function alertFace({ color } = {}) {
  const { FROG, DEEP, BOLD, RESET } = paint(color);
  return [
    `   ${FROG}╭───╮ ╭───╮${RESET}`,
    `   ${FROG}│ ${BOLD}⊙${RESET}${FROG} │ │ ${BOLD}⊙${RESET}${FROG} │${RESET}`,
    `   ${FROG}╰───╯ ╰───╯${RESET}`,
    `       ${DEEP}${BOLD}◯${RESET}`,
  ].join('\n');
}

// Happy closed eyes + smile: safe to deploy.
export function approveFace({ color } = {}) {
  const { FROG, BOLD, RESET } = paint(color);
  return [
    `   ${FROG}╭───╮ ╭───╮${RESET}`,
    `   ${FROG}│ ${BOLD}‿${RESET}${FROG} │ │ ${BOLD}‿${RESET}${FROG} │${RESET}`,
    `   ${FROG}╰───╯ ╰───╯${RESET}`,
    `      ${BOLD}‿‿${RESET}`,
  ].join('\n');
}
