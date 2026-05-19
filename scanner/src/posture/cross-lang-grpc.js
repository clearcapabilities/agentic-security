import { isChainWorthy, familyForBoundary } from './cross-lang-meta.js';

// gRPC / .proto cross-language taint propagation (Sentinel-parity FR-DET-3).
//
// When a project ships .proto files alongside server impls and client stubs,
// the engine can correlate them:
//
//   service UserService {
//     rpc GetUser(GetUserRequest) returns (User);
//   }
//
//   // server (Go / Java / Python / Node)
//   func (s *userServer) GetUser(ctx, req) (*User, error) { ... }
//
//   // client
//   resp, err := client.GetUser(ctx, &pb.GetUserRequest{...})
//
// We pair the GetUser call site (client) with the GetUser implementation
// (server). When the server implementation file has high+ findings, we emit
// a cross_language:true chain to the client call site so engineers see the
// transitive risk.

function parseProtoFiles(fileContents) {
  // Returns { services: Map<serviceName, {file, methods: Set<methodName>}> }
  const services = new Map();
  for (const [fp, c] of Object.entries(fileContents || {})) {
    if (!fp.endsWith('.proto')) continue;
    if (typeof c !== 'string' || c.length > 500_000) continue;
    const blockRe = /\bservice\s+(\w+)\s*\{([^}]*)\}/g;
    let bm;
    while ((bm = blockRe.exec(c))) {
      const svcName = bm[1];
      const body = bm[2] || '';
      const methods = new Set();
      const methodRe = /\brpc\s+(\w+)\s*\(/g;
      let mm;
      while ((mm = methodRe.exec(body))) methods.add(mm[1]);
      services.set(svcName, { file: fp, methods });
    }
  }
  return services;
}

// Find client-side gRPC call sites. The generated stubs call <ServiceName>Client
// (Go / Java / Node) or <service_name>Stub (Python) — but the method name on
// the receiver is what we match.
function findClientCalls(fileContents, services) {
  const allMethods = new Set();
  for (const s of services.values()) for (const m of s.methods) allMethods.add(m);
  if (!allMethods.size) return [];
  const found = [];
  for (const [fp, c] of Object.entries(fileContents || {})) {
    if (!c || typeof c !== 'string') continue;
    if (c.length > 500_000) continue;
    if (!/\.(?:js|jsx|ts|tsx|mjs|cjs|py|go|java|kt|rb|cs)$/i.test(fp)) continue;
    // <receiver>.<MethodName>(<ctx>, <req>)  — generic client invocation.
    // We look for any of the proto-declared method names being called on an
    // object that looks like a client (camelCase identifier ending in "Client"
    // or "Stub", OR any identifier when the method name is uncommon enough).
    const re = /\b(\w+)\s*\.\s*(\w+)\s*\(/g;
    let m;
    while ((m = re.exec(c))) {
      const methodName = m[2];
      if (!allMethods.has(methodName)) continue;
      const recv = m[1];
      // Heuristic: receiver name suggests "client" or "stub" — reduces FPs.
      // Skip generic names that are too common (.map, .filter, etc.).
      if (!/(?:client|stub|conn|svc|service)/i.test(recv)) continue;
      const line = c.substring(0, m.index).split('\n').length;
      found.push({ file: fp, line, method: methodName, receiver: recv,
                   snippet: (c.split('\n')[line - 1] || '').trim().slice(0, 200) });
    }
  }
  return found;
}

// Find server impls — methods on a struct/class that match a proto method.
function findServerImpls(fileContents, services) {
  const allMethods = new Set();
  for (const s of services.values()) for (const m of s.methods) allMethods.add(m);
  if (!allMethods.size) return [];
  const found = [];
  // Patterns vary by language:
  //   Go:    func (s *userServer) GetUser(ctx, req) (*User, error) {
  //   Java:  public User getUser(GetUserRequest req) {  (note: lower-cased)
  //   Python: def GetUser(self, request, context):
  //   Node:  async getUser(call, callback) {  (lower-camel)
  // We match on either the exact proto name OR its lower-camel variant.
  function expand(m) {
    return new Set([m, m.charAt(0).toLowerCase() + m.slice(1)]);
  }
  for (const [fp, c] of Object.entries(fileContents || {})) {
    if (!c || typeof c !== 'string') continue;
    if (c.length > 500_000) continue;
    if (!/\.(?:go|java|kt|py|rb|js|ts|cs)$/i.test(fp)) continue;
    for (const method of allMethods) {
      const variants = [...expand(method)];
      // Approximate detection: a function/method definition whose name is
      // one of the variants, AND the file has 'pb' / 'proto' / 'grpc' import.
      if (!/(?:grpc|pb|protobuf|protoc-gen|@grpc\/grpc-js|google\.protobuf)/i.test(c)) continue;
      const altList = variants.map(v => v.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|');
      // Accept any function-definition shape (Go, Java, Python, JS function /
      // arrow / class method) whose name is one of the proto-method variants
      // AND whose arg list starts with `<ident>,` (the gRPC call / context).
      const defRe = new RegExp(
        `\\b(?:func\\s+\\([^)]*\\)\\s+|public\\s+\\w[\\w<>,\\s]*\\s+|async\\s+|def\\s+|function\\s+|exports\\.\\s*)?` +
        `(?:${altList})\\s*\\(\\s*\\w+\\s*,`,
        'g'
      );
      let dm;
      while ((dm = defRe.exec(c))) {
        const line = c.substring(0, dm.index).split('\n').length;
        found.push({ file: fp, line, method,
                     snippet: (c.split('\n')[line - 1] || '').trim().slice(0, 200) });
      }
    }
  }
  return found;
}

export function scanCrossLangGrpc(fileContents, existingFindings) {
  const services = parseProtoFiles(fileContents);
  if (services.size === 0) return [];
  const clients = findClientCalls(fileContents, services);
  if (clients.length === 0) return [];
  const servers = findServerImpls(fileContents, services);
  if (servers.length === 0) return [];

  // Index findings by file — high+ AND chain-worthy only (FR-CHAIN-FILTER).
  const findingsByFile = new Map();
  for (const f of existingFindings || []) {
    if (!f.file || !/critical|high/i.test(f.severity || '')) continue;
    if (!isChainWorthy(f)) continue;
    if (!findingsByFile.has(f.file)) findingsByFile.set(f.file, []);
    findingsByFile.get(f.file).push(f);
  }

  const out = [];
  for (const c of clients) {
    const impls = servers.filter(s => s.method === c.method);
    for (const impl of impls) {
      const fs = findingsByFile.get(impl.file) || [];
      if (!fs.length) continue;
      const seed = fs[0];
      out.push({
        id: `xlang-grpc:${c.file}:${c.line}:${c.method}`,
        file: c.file, line: c.line,
        vuln: `Cross-Language Taint (gRPC): client call → ${c.method} (server impl in ${impl.file}:${impl.line} carries ${seed.severity})`,
        severity: 'high',
        cwe: seed.cwe || 'CWE-862',
        snippet: c.snippet,
        remediation: `The gRPC method ${c.method} is implemented in ${impl.file}:${impl.line} where "${seed.vuln}" was reported. Any client that propagates the response into a sensitive sink inherits the underlying risk. Fix the server-side finding first.`,
        parser: 'XLANG-GRPC',
        family: familyForBoundary('grpc'),   // FR-FAMILY-REGISTRY
        confidence: 0.65,
        cross_language: true,
        chain: [
          { file: c.file,   line: c.line,   label: `client.${c.method}` },
          { file: impl.file, line: impl.line, label: `impl ${impl.method}` },
          { file: seed.file, line: seed.line, label: seed.vuln },
        ],
      });
    }
  }
  return out;
}
