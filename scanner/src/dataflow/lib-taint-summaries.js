// Library taint summaries — Recommendation #5 of the SCA/SAST plan.
//
// Hand-curated knowledge that "this library method returns tainted data" or
// "this method propagates taint from arg N to its return." Used by the
// existing dataflow engine + per-language detectors when classifying the
// taint state of a declaration's rhs.
//
// The summaries are intentionally per-language because the same concept
// (a user-input source) has different idioms in each ecosystem. Each entry:
//
//   { pattern: RegExp, kind: 'source' | 'sanitizer' | 'passthrough',
//     framework: 'spring' | 'aspnet' | 'glibc' | … }
//
// Kinds:
//   source       — return value is unconditionally tainted
//   sanitizer    — return value is unconditionally clean, even if any arg
//                  was tainted (e.g. HtmlEncode, parameterized prepare)
//   passthrough  — return value is tainted iff arg N is tainted (taint
//                  flows through). Not modelled in v1; reserved for future
//                  inter-procedural extensions (Recommendation #9).
//
// Usage: detectors call `isLibrarySource(text, lang)` and `isLibrarySanitizer
// (text, lang)` to refine their per-call decisions.

const JAVA_SUMMARIES = {
  sources: [
    // Servlet API — every request-scoped getter is a user-input source.
    /\bHttpServletRequest\b[\s\S]{0,2000}?\.\s*(?:getParameter(?:Values|Map)?|getQueryString|getHeader(?:Names)?|getInputStream|getReader|getCookies?|getRequestURI|getRequestURL|getQueryString|getPathInfo)\s*\(/,
    /\bjavax\.servlet\.http\.HttpServletRequest\b/,
    // Spring MVC — controller method annotations bind to request data.
    /@RequestParam\b/,
    /@RequestBody\b/,
    /@PathVariable\b/,
    /@RequestHeader\b/,
    /@CookieValue\b/,
    /@ModelAttribute\b/,
    // Spring Security — the principal is user-controlled in the trust sense
    // (it identifies WHO the request is from; not auto-sanitized).
    /\bSecurityContextHolder\s*\.\s*getContext\s*\(\s*\)\s*\.\s*getAuthentication\s*\(\s*\)/,
    // Java Files API — file content is untrusted when source is unknown.
    /\bFiles\s*\.\s*(?:readString|readAllBytes|readAllLines|lines|newBufferedReader|newInputStream)\b/,
    /\bPaths\s*\.\s*get\s*\([^)]*(?:System\.getProperty|args)\b/,
    // BufferedReader / Scanner reading user input.
    /\bBufferedReader\b[\s\S]{0,500}?\.\s*readLine\s*\(/,
    /\bScanner\b[\s\S]{0,500}?\.\s*(?:next(?:Line)?|nextInt|nextLong)\s*\(/,
    // System.getenv / System.getProperty — environment is configurable.
    /\bSystem\s*\.\s*(?:getenv|getProperty)\s*\(/,
    // Jackson — deserialization input is untrusted.
    /\bObjectMapper\b[\s\S]{0,500}?\.\s*readValue\s*\(/,
    /\bJsonParser\b[\s\S]{0,500}?\.\s*getValueAsString\s*\(/,
    // Apache Commons IO.
    /\bIOUtils\s*\.\s*toString\s*\(/,
    /\bFileUtils\s*\.\s*readFileToString\s*\(/,
    // Spring WebFlux ServerWebExchange.
    /\bServerWebExchange\b[\s\S]{0,500}?\.\s*getRequest\s*\(/,
  ],
  sanitizers: [
    /\bOWASP\.Encoder\b/,
    /\bESAPI\b[\s\S]{0,200}?\.\s*encoder\s*\(\s*\)/,
    /\bStringEscapeUtils\s*\.\s*escape(?:Html\d?|Xml|Sql|Java|JavaScript)\b/,
    /\bHtmlUtils\s*\.\s*htmlEscape\b/,
    /\bUriUtils\s*\.\s*encode\b/,
    // JDBC PreparedStatement parameter setters — taint is cleaned at bind.
    /\bPreparedStatement\b[\s\S]{0,500}?\.\s*set(?:String|Int|Long|Object|BigDecimal|Date|Timestamp)\s*\(/,
    /\bNamedParameterJdbcTemplate\b[\s\S]{0,500}?\.\s*(?:query|update|queryForObject)\s*\([^,]+,\s*new\s+MapSqlParameterSource\b/,
    // Java validators.
    /\bjakarta\.validation\b/,
    /\bjavax\.validation\b/,
    /\b@Valid\b/,
  ],
};

const CSHARP_SUMMARIES = {
  sources: [
    // ASP.NET request surfaces.
    /\bHttpRequest\b[\s\S]{0,500}?\.\s*(?:Query|Form|Headers|Cookies|RouteValues|Body|InputStream|QueryString|Params|Path|Url)\b/,
    /\bHttpContext\s*\.\s*Request\b/,
    /\bIFormCollection\b/,
    /\bIFormFile\b/,
    /\bIFormFileCollection\b/,
    // ASP.NET Core model binding.
    /\[FromQuery\]/,
    /\[FromBody\]/,
    /\[FromForm\]/,
    /\[FromRoute\]/,
    /\[FromHeader\]/,
    // Configuration may carry secrets but the VALUES are environment-supplied.
    /\bIConfiguration\b[\s\S]{0,500}?\.\s*(?:GetSection|GetValue|GetConnectionString|GetChildren)\s*\(/,
    // Newtonsoft.Json deserialization.
    /\bJsonConvert\s*\.\s*Deserialize(?:Object|XmlNode)\s*</,
    /\bJsonSerializer\s*\.\s*Deserialize\s*</,
    // Files / streams.
    /\bFile\s*\.\s*(?:ReadAllText|ReadAllLines|ReadAllBytes|OpenRead|OpenText)\s*\(/,
    /\bStreamReader\b[\s\S]{0,500}?\.\s*(?:ReadLine|ReadToEnd|Read)\s*\(/,
    /\bBinaryReader\b[\s\S]{0,500}?\.\s*Read(?:String|Bytes|Char|Int32|Int64|UInt32|UInt64)\s*\(/,
    // Network reads.
    /\bWebClient\b[\s\S]{0,500}?\.\s*Download(?:String|Data|File)\s*\(/,
    /\bHttpClient\b[\s\S]{0,500}?\.\s*(?:GetAsync|GetStringAsync|PostAsync|SendAsync)\s*\(/,
    // Environment + console.
    /\bEnvironment\s*\.\s*GetEnvironmentVariable\s*\(/,
    /\bConsole\s*\.\s*ReadLine\s*\(/,
  ],
  sanitizers: [
    /\bHttpUtility\s*\.\s*HtmlEncode\b/,
    /\bHtmlEncoder\s*\.\s*Default\s*\.\s*Encode\b/,
    /\bAntiXssEncoder\b/,
    /\bSqlParameter\b/,
    /\bMySqlParameter\b/,
    /\bNpgsqlParameter\b/,
    // EF Core parameterized helpers.
    /\bFromSqlInterpolated\s*\(/,
    // Validation.
    /\bint\s*\.\s*TryParse\s*\(/,
    /\bGuid\s*\.\s*TryParse\s*\(/,
    /\bDateTime\s*\.\s*TryParse\s*\(/,
    /\bRegex\s*\.\s*Replace\s*\(/,
  ],
};

const CPP_SUMMARIES = {
  sources: [
    // POSIX — environment + user input.
    /\bgetenv\s*\(/,
    /\bsecure_getenv\s*\(/,
    /\bargv\s*\[/,
    /\bgets\s*\(/,
    /\bfgets\s*\(/,
    /\bscanf\s*\(/,
    /\bfscanf\s*\(/,
    /\bgetc\s*\(/,
    /\bfgetc\s*\(/,
    /\bread\s*\(\s*\d+/,    // unistd read(fd, ...)
    /\brecv\s*\(/,
    /\brecvfrom\s*\(/,
    // OpenSSL / network.
    /\bBIO_read\s*\(/,
    /\bSSL_read\s*\(/,
    // Win32 input.
    /\bGetCommandLine[AW]?\s*\(/,
    /\bGetEnvironmentVariable[AW]?\s*\(/,
    // Standard streams.
    /\bstd\s*::\s*cin\s*>>/,
    /\bstd\s*::\s*getline\s*\(\s*std\s*::\s*cin\b/,
  ],
  sanitizers: [
    // Length-checked copies (best-effort).
    /\bstrncpy\s*\(\s*[^,]+,\s*[^,]+,\s*sizeof\s*\(/,
    /\bsnprintf\s*\(\s*[^,]+,\s*sizeof\s*\(/,
    /\bisdigit\s*\(/,
    /\bisalpha\s*\(/,
    /\bisalnum\s*\(/,
    /\bstrtol\s*\(/,
    /\bstrtoul\s*\(/,
  ],
};

const SUMMARIES_BY_LANG = {
  java:   JAVA_SUMMARIES,
  csharp: CSHARP_SUMMARIES,
  cpp:    CPP_SUMMARIES,
  c:      CPP_SUMMARIES,
};

// Resolve language from a file path or explicit hint.
function _langOf(hint, file) {
  if (hint) return hint;
  if (!file) return null;
  if (/\.java$/i.test(file)) return 'java';
  if (/\.cs$/i.test(file)) return 'csharp';
  if (/\.(?:c|cc|cpp|cxx|h|hh|hpp)$/i.test(file)) return 'cpp';
  return null;
}

/**
 * Returns true if `text` contains a library-source pattern for the language.
 */
export function isLibrarySource(text, langOrFile) {
  if (!text) return false;
  const lang = _langOf(typeof langOrFile === 'string' && langOrFile.includes('.') ? null : langOrFile, langOrFile);
  const s = SUMMARIES_BY_LANG[lang];
  if (!s) return false;
  for (const re of s.sources) if (re.test(text)) return true;
  return false;
}

/**
 * Returns true if `text` contains a library-sanitizer pattern for the language.
 */
export function isLibrarySanitizer(text, langOrFile) {
  if (!text) return false;
  const lang = _langOf(typeof langOrFile === 'string' && langOrFile.includes('.') ? null : langOrFile, langOrFile);
  const s = SUMMARIES_BY_LANG[lang];
  if (!s) return false;
  for (const re of s.sanitizers) if (re.test(text)) return true;
  return false;
}

export const _internals = { JAVA_SUMMARIES, CSHARP_SUMMARIES, CPP_SUMMARIES, SUMMARIES_BY_LANG };
