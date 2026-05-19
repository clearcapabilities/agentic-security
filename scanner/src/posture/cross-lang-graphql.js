import { isChainWorthy, familyForBoundary } from './cross-lang-meta.js';

// GraphQL resolver-to-resolver cross-language taint (Sentinel-parity FR-DET-3).
//
// Parses GraphQL SDL files (.graphql / .gql / .schema.graphql) and detects
// resolver implementations. When a high+ finding sits inside one resolver,
// and another resolver references the same Type/field via parent/context,
// the engine reports a cross-resolver chain.
//
// We also catch client query call sites (Apollo Client, urql, graphql-request)
// referencing a Query/Mutation by name and pair them with the server resolver
// the same way the OpenAPI module pairs HTTP routes.

function parseSchemas(fileContents) {
  // Returns { types: Map<typeName, {fields: Map<fieldName, {file, line, returnType?}>}>,
  //           queries: Map<queryName, {file, line, returnType?}>,
  //           mutations: Map<mutationName, ...> }
  const types = new Map();
  const queries = new Map();
  const mutations = new Map();
  for (const [fp, c] of Object.entries(fileContents || {})) {
    if (!/\.(?:graphql|gql|schema\.graphql)$/i.test(fp)) continue;
    if (typeof c !== 'string' || c.length > 500_000) continue;
    // Type declarations: type X { field: T  field2(arg: Y): Z }
    const typeRe = /\btype\s+(\w+)\s*(?:implements\s+[^{]+)?\{([\s\S]*?)\}/g;
    let tm;
    while ((tm = typeRe.exec(c))) {
      const tName = tm[1];
      const body = tm[2];
      const fields = new Map();
      const fieldRe = /^\s*(\w+)\s*(?:\([^)]*\))?\s*:\s*([\w!\[\]]+)/gm;
      let fm;
      while ((fm = fieldRe.exec(body))) {
        const line = c.substring(0, tm.index + (fm.index || 0)).split('\n').length;
        fields.set(fm[1], { file: fp, line, returnType: fm[2] });
      }
      if (tName === 'Query') for (const [k, v] of fields) queries.set(k, v);
      else if (tName === 'Mutation') for (const [k, v] of fields) mutations.set(k, v);
      else types.set(tName, { fields });
    }
  }
  return { types, queries, mutations };
}

// Detect server resolvers. Patterns vary by framework:
//   Apollo Server: const resolvers = { Query: { foo(parent, args, ctx) {...} } }
//   GraphQL-JS:    new GraphQLSchema({ types: ..., resolve(parent, args, ctx) }
//   NestJS:        @Query() foo() {} / @Mutation() / @ResolveField()
//   Hot Chocolate (.NET): [ExtendObjectType(Name="Query")] ... GetFoo(...)
//   Strawberry / Graphene (Python): @strawberry.field def foo(): ...
function findResolvers(fileContents, schema) {
  const found = [];
  const allKnown = new Set([
    ...schema.queries.keys(),
    ...schema.mutations.keys(),
  ]);
  for (const t of schema.types.values()) for (const k of t.fields.keys()) allKnown.add(k);
  if (!allKnown.size) return found;

  for (const [fp, c] of Object.entries(fileContents || {})) {
    if (!c || typeof c !== 'string') continue;
    if (c.length > 500_000) continue;
    if (!/\.(?:js|jsx|ts|tsx|mjs|cjs|py|cs|rb|go|java|kt)$/i.test(fp)) continue;
    // Only spend regex budget on files that look graphql-related. Heuristics:
    //   - content references graphql / apollo / gql backticks / NestJS / Strawberry / Graphene
    //   - filename contains "resolver", "schema", "graphql", "mutation", "query"
    const looksGraphqlByContent = /(?:graphql|GraphQL|apollo|@nestjs\/graphql|strawberry|graphene|HotChocolate|gql\s*`|const\s+resolvers\s*=)/i.test(c);
    const looksGraphqlByName    = /(?:resolver|schema|graphql|mutations?|queries?)\b/i.test(fp);
    if (!looksGraphqlByContent && !looksGraphqlByName) continue;

    for (const fieldName of allKnown) {
      // Property-style resolver:  fieldName(parent, args, ctx) { ... }
      // Or: fieldName: async (parent, args, ctx) => ...
      const reA = new RegExp(`\\b${fieldName}\\s*\\(\\s*\\w+\\s*,\\s*\\w+\\s*,\\s*\\w+\\s*\\)\\s*\\{`, 'g');
      const reB = new RegExp(`\\b${fieldName}\\s*:\\s*(?:async\\s+)?\\(?\\s*\\w+\\s*,\\s*\\w+\\s*,\\s*\\w+\\s*\\)?\\s*=>`, 'g');
      // NestJS decorator: @Query(() => X) async fieldName(...)
      const reC = new RegExp(`@(?:Query|Mutation|ResolveField)\\s*\\([^)]*\\)\\s*\\n?\\s*(?:async\\s+)?${fieldName}\\s*\\(`, 'g');
      // Python decorator: @strawberry.field def field_name(...)
      const snakeName = fieldName.replace(/[A-Z]/g, (s, i) => (i ? '_' : '') + s.toLowerCase());
      const reD = new RegExp(`@strawberry\\.field\\s*(?:\\([^)]*\\))?\\s*def\\s+${snakeName}\\s*\\(`, 'g');

      for (const re of [reA, reB, reC, reD]) {
        let m;
        while ((m = re.exec(c))) {
          const line = c.substring(0, m.index).split('\n').length;
          found.push({ file: fp, line, field: fieldName,
                       snippet: (c.split('\n')[line - 1] || '').trim().slice(0, 200) });
        }
      }
    }
  }
  return found;
}

// Client query call sites. Apollo / urql / graphql-request style:
//   useQuery(GET_USER) / client.query({query: GET_USER}) / gql`query { user { ... } }`
function findClientQueries(fileContents, schema) {
  const allKnown = new Set([...schema.queries.keys(), ...schema.mutations.keys()]);
  if (!allKnown.size) return [];
  const found = [];
  for (const [fp, c] of Object.entries(fileContents || {})) {
    if (!c || typeof c !== 'string') continue;
    if (c.length > 500_000) continue;
    if (!/\.(?:js|jsx|ts|tsx|mjs|cjs|py|go)$/i.test(fp)) continue;
    if (!/(?:gql\s*`|useQuery|useMutation|client\.query\(|client\.mutate\(|graphql\s*`)/i.test(c)) continue;
    // Look for `gql`query { fieldName ...`` patterns or `mutation { fieldName ...`
    for (const queryName of allKnown) {
      const re = new RegExp(`(?:query|mutation)\\b[^\`]{0,400}?\\b${queryName}\\s*[\\(\\{]`, 'g');
      let m;
      while ((m = re.exec(c))) {
        const line = c.substring(0, m.index).split('\n').length;
        found.push({ file: fp, line, query: queryName,
                     snippet: (c.split('\n')[line - 1] || '').trim().slice(0, 200) });
      }
    }
  }
  return found;
}

export function scanCrossLangGraphql(fileContents, existingFindings) {
  const schema = parseSchemas(fileContents);
  const totalDecls = schema.queries.size + schema.mutations.size + schema.types.size;
  if (totalDecls === 0) return [];

  const resolvers = findResolvers(fileContents, schema);
  if (resolvers.length === 0) return [];
  const clients = findClientQueries(fileContents, schema);

  const findingsByFile = new Map();
  for (const f of existingFindings || []) {
    if (!f.file || !/critical|high/i.test(f.severity || '')) continue;
    if (!isChainWorthy(f)) continue;   // FR-CHAIN-FILTER
    if (!findingsByFile.has(f.file)) findingsByFile.set(f.file, []);
    findingsByFile.get(f.file).push(f);
  }

  const out = [];
  for (const c of clients) {
    const impls = resolvers.filter(r => r.field === c.query);
    for (const impl of impls) {
      const fs = findingsByFile.get(impl.file) || [];
      if (!fs.length) continue;
      const seed = fs[0];
      out.push({
        id: `xlang-graphql:${c.file}:${c.line}:${c.query}`,
        file: c.file, line: c.line,
        vuln: `Cross-Language Taint (GraphQL): query ${c.query} → resolver in ${impl.file}:${impl.line} carries ${seed.severity}`,
        severity: 'high',
        cwe: seed.cwe || 'CWE-862',
        snippet: c.snippet,
        remediation: `The GraphQL field "${c.query}" is resolved at ${impl.file}:${impl.line} where "${seed.vuln}" was reported. Fix the resolver-side finding first; any client that consumes the response inherits the underlying risk.`,
        parser: 'XLANG-GRAPHQL',
        family: familyForBoundary('graphql'),   // FR-FAMILY-REGISTRY
        confidence: 0.6,
        cross_language: true,
        chain: [
          { file: c.file,    line: c.line,    label: `query ${c.query}` },
          { file: impl.file, line: impl.line, label: `resolver ${impl.field}` },
          { file: seed.file, line: seed.line, label: seed.vuln },
        ],
      });
    }
  }
  return out;
}
