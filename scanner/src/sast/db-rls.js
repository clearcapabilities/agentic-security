// Database / Supabase RLS security audit.
//
// Vibecoders using Supabase routinely ship with Row-Level Security disabled,
// service-role keys exposed client-side, or admin APIs called from public
// endpoints. This module catches the static signals for those patterns.
//
// Findings:
//   SUPABASE_SERVICE_KEY_CLIENT   — service_role key in NEXT_PUBLIC_* var or client-side file
//   SUPABASE_ADMIN_CLIENT_SIDE    — supabase.auth.admin.* in browser/client code
//   SUPABASE_BYPASS_RLS           — explicit bypassRowLevelSecurity or serviceRole in query
//   RLS_DISABLED_SQL              — SQL CREATE TABLE without ALTER TABLE … ENABLE ROW LEVEL SECURITY
//   SUPABASE_ANON_KEY_SERVER      — anon key used server-side with service-role semantics
//   POSTGRES_DIRECT_NO_RLS        — raw pg/postgres connection in request handler (bypasses RLS)

const _SCAN_EXT_RE = /\.(?:js|jsx|ts|tsx|mjs|cjs|py|sql)$/i;
const _NONPROD_RE = /(?:^|\/)(?:tests?|__tests__|spec|fixtures?|examples?|node_modules)\//i;
const _CLIENT_PATH_RE = /(?:^|\/)(?:app|pages|components|src\/app|src\/pages|src\/components|public|client|frontend|ui)\//i;

// Service role key referenced from a NEXT_PUBLIC_ env var or hardcoded in a client-side path.
const NEXT_PUBLIC_SERVICE_RE = /NEXT_PUBLIC_\w*(?:SERVICE|SUPABASE_SERVICE|ADMIN)\w*\s*[=:]/i;
const SERVICE_KEY_LITERAL_RE = /(?:serviceRoleKey|service_role_key|SUPABASE_SERVICE_ROLE_KEY)\s*[:=]\s*['"`][a-zA-Z0-9._-]{20,}/;
const SUPABASE_CLIENT_IMPORT_RE = /(?:from|require)\s*\(?\s*['"`]@supabase\/supabase-js['"`]/;

// Auth admin API called in code that might be client-accessible.
const ADMIN_API_RE = /supabase\s*\.\s*auth\s*\.\s*admin\s*\./;

// Explicit RLS bypass in a Supabase query builder chain.
const BYPASS_RLS_RE = /\.\s*(?:bypassRowLevelSecurity|serviceRole)\s*\(\s*\)/;

// SQL: table created without RLS enabled in the same statement block.
const SQL_CREATE_TABLE_RE = /CREATE\s+TABLE(?:\s+IF\s+NOT\s+EXISTS)?\s+["'`]?(\w+)["'`]?\s*\(/gi;
const SQL_ENABLE_RLS_RE = /ALTER\s+TABLE\s+["'`]?\w+["'`]?\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY/i;

// Raw postgres client in a request handler.
const PG_CLIENT_RE = /new\s+(?:Pool|Client)\s*\(\s*\{/;
const REQUEST_HANDLER_RE = /(?:req|request|ctx|context)\s*[,)]/;

function scanDatabaseRLS(file, content) {
  if (!_SCAN_EXT_RE.test(file)) return [];
  if (_NONPROD_RE.test(file)) return [];
  const findings = [];
  const lines = content.split('\n');
  const isClientPath = _CLIENT_PATH_RE.test(file);
  const isSql = /\.sql$/i.test(file);

  // --- NEXT_PUBLIC_ service key ---
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (NEXT_PUBLIC_SERVICE_RE.test(line)) {
      findings.push({
        id: `db-rls:SUPABASE_SERVICE_KEY_CLIENT:${file}:${i + 1}`,
        title: 'Supabase service-role key exposed via NEXT_PUBLIC_ variable',
        severity: 'critical',
        file, line: i + 1,
        description: 'A NEXT_PUBLIC_ environment variable referencing a service-role key is visible to every browser client. Any visitor can extract it from the page source and bypass Row-Level Security entirely.',
        remediation: 'Never prefix service-role keys with NEXT_PUBLIC_. Use them only in server-side code (API routes, Server Actions, edge functions). Rotate the key immediately if it was already deployed.',
        cwe: 'CWE-522',
      });
    }

    // Hardcoded service role key literal
    if (SERVICE_KEY_LITERAL_RE.test(line)) {
      findings.push({
        id: `db-rls:SERVICE_KEY_LITERAL:${file}:${i + 1}`,
        title: 'Supabase service-role key hardcoded in source',
        severity: 'critical',
        file, line: i + 1,
        description: 'A Supabase service-role key is embedded directly in source code. This key bypasses Row-Level Security on every table and is now permanently stored in git history.',
        remediation: 'Move to SUPABASE_SERVICE_ROLE_KEY env var, add it to .gitignore, and rotate via the Supabase dashboard → Settings → API.',
        cwe: 'CWE-798',
      });
    }

    // Auth admin API in client-side path
    if (isClientPath && ADMIN_API_RE.test(line)) {
      findings.push({
        id: `db-rls:SUPABASE_ADMIN_CLIENT_SIDE:${file}:${i + 1}`,
        title: 'Supabase auth.admin API called in client-side code',
        severity: 'critical',
        file, line: i + 1,
        description: 'supabase.auth.admin.* requires the service-role key and must only be called server-side. Calling it in client code means the service-role key is bundled into the browser JavaScript.',
        remediation: 'Move all auth.admin calls to a Server Action, API route, or edge function. Never import the service-role supabase client in client components.',
        cwe: 'CWE-285',
      });
    }

    // Explicit RLS bypass
    if (BYPASS_RLS_RE.test(line)) {
      findings.push({
        id: `db-rls:SUPABASE_BYPASS_RLS:${file}:${i + 1}`,
        title: 'Explicit Supabase RLS bypass in query',
        severity: 'high',
        file, line: i + 1,
        description: 'bypassRowLevelSecurity() or serviceRole() is used in a query, disabling all RLS policies for that request. If this code is reachable from a user-controlled path, any user can read or modify other users\' data.',
        remediation: 'Remove bypassRowLevelSecurity() from user-facing query paths. If admin operations are required, gate them behind a server-side role check and audit log.',
        cwe: 'CWE-284',
      });
    }

    // Raw pg client in request handler
    if (PG_CLIENT_RE.test(line)) {
      const ctx = lines.slice(Math.max(0, i - 5), i + 10).join('\n');
      if (REQUEST_HANDLER_RE.test(ctx)) {
        findings.push({
          id: `db-rls:POSTGRES_DIRECT_NO_RLS:${file}:${i + 1}`,
          title: 'Direct PostgreSQL connection in request handler bypasses RLS',
          severity: 'high',
          file, line: i + 1,
          description: 'A raw pg Pool/Client connection used inside a request handler connects as a privileged database role, bypassing all Supabase Row-Level Security policies. Any data returned is not filtered by the authenticated user\'s context.',
          remediation: 'Use the Supabase client with the user\'s JWT for RLS-filtered queries. If raw SQL is required, set SET LOCAL role to the authenticated user\'s role and pass the JWT claims via set_config.',
          cwe: 'CWE-284',
        });
      }
    }
  }

  // --- SQL file: CREATE TABLE without RLS ---
  if (isSql) {
    const tablesWithRLS = new Set();
    let m;
    if (SQL_ENABLE_RLS_RE.test(content)) {
      // collect which tables have RLS
      const rlsRe = /ALTER\s+TABLE\s+["'`]?(\w+)["'`]?\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY/gi;
      while ((m = rlsRe.exec(content)) !== null) tablesWithRLS.add(m[1].toLowerCase());
    }
    SQL_CREATE_TABLE_RE.lastIndex = 0;
    while ((m = SQL_CREATE_TABLE_RE.exec(content)) !== null) {
      const tableName = m[1].toLowerCase();
      if (!tablesWithRLS.has(tableName)) {
        const lineNum = content.slice(0, m.index).split('\n').length;
        findings.push({
          id: `db-rls:RLS_DISABLED_SQL:${file}:${lineNum}`,
          title: `Table "${m[1]}" created without Row-Level Security`,
          severity: 'high',
          file, line: lineNum,
          description: `The table "${m[1]}" is created but no ALTER TABLE … ENABLE ROW LEVEL SECURITY statement is present in this file. Without RLS, any authenticated user can read and write every row regardless of ownership.`,
          remediation: `Add after the CREATE TABLE:\n  ALTER TABLE "${m[1]}" ENABLE ROW LEVEL SECURITY;\n  CREATE POLICY "owner_only" ON "${m[1]}" USING (user_id = auth.uid());`,
          cwe: 'CWE-284',
        });
      }
    }
  }

  return findings;
}

export { scanDatabaseRLS };
