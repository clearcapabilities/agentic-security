import { runScan } from './src/runScan.js';
const root = 'test/benchmark/realworld/.bench-cache/owasp-benchmark-b06d6efaebd577a327514364951916e7df3290b4-blinded-nocomment/src/main/java/org/owasp/benchmark/testcode';
process.env.AGENTIC_SECURITY_BLIND_BENCH = '1';
const { scan } = await runScan(root);
const all = [...(scan.findings||[]), ...(scan.logicVulns||[]), ...(scan.secrets||[])];
const byParser = new Map();
for (const f of all) {
  const p = f.parser || '(default-pattern)';
  byParser.set(p, (byParser.get(p)||0) + 1);
}
console.log('Parser distribution on OWASP Benchmark v1.2 (blinded-nocomment, BLIND_BENCH=1):');
for (const [p, n] of [...byParser.entries()].sort((a,b)=>b[1]-a[1])) {
  console.log('  ' + p.padEnd(40) + ' ' + n);
}
const bs = ['juliet', 'bench-shape', 'bench-extras', 'primary-cwe'];
const leakers = all.filter(f => {
  const s = (String(f.parser||'') + ' ' + String(f.family||'') + ' ' + String(f.vuln||'')).toLowerCase();
  return bs.some(e => s.includes(e));
});
console.log('\nFindings whose parser/family/vuln mentions a bench-shape source: ' + leakers.length);
for (const f of leakers.slice(0,10)) console.log('  ' + (f.parser||'?') + ' | ' + (f.family||'?') + ' | ' + (f.vuln||'').slice(0,60));
