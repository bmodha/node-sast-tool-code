export function decideGate(input, policy) {
  if (input.suppressed) return "clear";
  if (input.waived) return "comment";
  if (input.system2Only) return "comment";
  if (input.classId === "secrets" && policy.block_on_secret && input.precision === "high") return "block";
  if (input.classId === "security_config" && input.risk === "critical" && policy.block_on_critical_iac) return "block";
  if (
    policy.block_high_precision_on_restricted
    && input.dataClass === "restricted"
    && input.precision === "high"
    && (input.risk === "high" || input.risk === "critical")
  ) return "block";
  return "comment";
}

export function checkFromFindings(findings) {
  return findings.some((finding) => finding.gate === "block") ? "failure" : "success";
}

export const CWE = {
  injection: ["CWE-89"],
  xss: ["CWE-79"],
  path_file: ["CWE-22"],
  secrets: ["CWE-798"],
  security_config: ["CWE-16"],
  supply_chain: ["CWE-1395"],
  resource_consumption: ["CWE-400"],
  deserialization: ["CWE-502"],
  ssrf_url: ["CWE-601"],
  cryptography: ["CWE-328"],
  session_token: ["CWE-613"],
  authentication: ["CWE-287"],
  access_control: ["CWE-915"],
  sensitive_data: ["CWE-200"],
  controls_errors: ["CWE-209"],
};

export const CLASS_LABELS = {
  injection: "Injection",
  xss: "Cross-site scripting",
  path_file: "Path and file",
  secrets: "Secrets",
  security_config: "Security configuration",
  supply_chain: "Supply chain",
  resource_consumption: "Resource consumption",
  deserialization: "Deserialization",
  ssrf_url: "Request forgery",
  cryptography: "Cryptography",
  session_token: "Session",
  authentication: "Authentication",
  access_control: "Access control",
  sensitive_data: "Sensitive data",
  controls_errors: "Error handling",
};

const JS = ["js", "jsx"];

function detector(entry) {
  return {
    languages: JS,
    evidenceType: "unsafe_call",
    sourcePatterns: ["non-literal"],
    sinkPatterns: [],
    sanitizers: [],
    confidenceBasis: "",
    limitations: "",
    collapse: true,
    defaultPattern: "",
    patternPrecision: {},
    patternNext: {},
    ...entry,
  };
}

export const RULES = {
  "js.sqli.string-concat": detector({
    classId: "injection", taxonomyId: "query-built-from-input", precision: "high", risk: "high", cwe: ["CWE-89"],
    title: "SQL built by concatenating a query string",
    next: "Confirm this value reaches a query call",
    defaultPattern: "sql",
    sourcePatterns: ["request", "non-literal"],
    sinkPatterns: ["string concatenation", "template literal", "ORDER BY fragment"],
    sanitizers: ["bound parameter"],
    confidenceBasis: "The query text is built with a non-literal value.",
    limitations: "Blind, time-based, UNION, stacked, and second-order SQL are the same sink. Statement type is not a separate finding.",
  }),
  "js.sql.literal": detector({
    classId: "injection", taxonomyId: "query-built-from-input", precision: "low", risk: "low", cwe: ["CWE-89"],
    title: "SQL query literal",
    next: "Confirm the query is parameterized",
    defaultPattern: "sql",
    sourcePatterns: ["literal"],
    sinkPatterns: ["SQL literal"],
    sanitizers: ["approved control likeness"],
    confidenceBasis: "A SQL-shaped literal is present. It may already be parameterized.",
    limitations: "Dropped when the concatenation rule covers the same statement.",
  }),
  "js.xss.dangerous-html": detector({
    classId: "xss", taxonomyId: "unsafe-html-sink", precision: "high", risk: "high", cwe: ["CWE-79"],
    title: "Unsanitized HTML sink",
    next: "Confirm this HTML is not taken from a request",
    defaultPattern: "html",
    sourcePatterns: ["request", "non-literal"],
    sinkPatterns: ["dangerouslySetInnerHTML", "innerHTML", "response HTML string"],
    sanitizers: ["text assignment", "escaped text"],
    confidenceBasis: "A markup string or HTML sink receives a non-literal value.",
    limitations: "Reflected, stored, DOM, and context variants are not separated. Repeated copies of the same sink in one file are one finding that lists each line.",
  }),
  "js.eval.member": detector({
    classId: "injection", taxonomyId: "dynamic-code", precision: "high", risk: "high", cwe: ["CWE-94"],
    title: "Dynamic eval of a non-literal value",
    next: "Confirm this call does not run request data",
    defaultPattern: "eval",
    sinkPatterns: ["member eval", "Function constructor"],
    sanitizers: ["fixed function call"],
    confidenceBasis: "eval or Function is called with a non-literal.",
    limitations: "Does not prove the argument is attacker-controlled.",
  }),
  "js.deser.unserialize": detector({
    classId: "deserialization", taxonomyId: "unsafe-deserialize", precision: "high", risk: "high", cwe: ["CWE-502"],
    title: "Unserialize call",
    next: "Confirm this parser is not given untrusted data",
    defaultPattern: "unserialize",
    sinkPatterns: ["unserialize", "yaml.load", "unsafeLoad"],
    sanitizers: ["safe load", "JSON parse of a checked shape"],
    confidenceBasis: "A deserializer known to accept object graphs is called.",
    limitations: "Pickle, Java, and .NET need other parsers. No gadget chain is reconstructed.",
  }),
  "js.redirect.request": detector({
    classId: "ssrf_url", taxonomyId: "untrusted-redirect", precision: "high", risk: "high", cwe: ["CWE-601"],
    title: "Redirect target comes from the request",
    next: "Confirm the redirect target is a fixed path",
    defaultPattern: "redirect",
    sourcePatterns: ["request", "Host header"],
    sinkPatterns: ["redirect"],
    sanitizers: ["fixed path"],
    confidenceBasis: "The redirect target is request data or the Host header.",
    limitations: "Allowlist bypass and parser discrepancies are not visible here.",
  }),
  "js.xml.entities": detector({
    classId: "injection", taxonomyId: "xml-entity-expansion", precision: "high", risk: "high", cwe: ["CWE-611"],
    title: "XML parser has entity substitution enabled",
    next: "Confirm entity substitution is required for this parser",
    defaultPattern: "xml",
    sinkPatterns: ["parseXml", "parseXmlString"],
    sanitizers: ["entity substitution disabled"],
    confidenceBasis: "The parser options set noent to true.",
    limitations: "External DTD, XInclude, and entity expansion share this option.",
  }),
  "js.crypto.md5-token": detector({
    classId: "cryptography", taxonomyId: "crypto-misuse", precision: "medium", risk: "medium",
    cwe: ["CWE-327", "CWE-328", "CWE-208"],
    title: "Weak cryptography used for a security value",
    next: "Confirm this value is not a token, password, or cipher input",
    defaultPattern: "weak-hash",
    sinkPatterns: ["md5", "sha1", "Math.random", "createCipheriv", "equality"],
    sanitizers: ["modern digest", "randomBytes", "random IV", "timing-safe compare"],
    confidenceBasis: "A weak algorithm, a static IV, Math.random, or an ordinary secret comparison is in source.",
    limitations: "Ordinary equality that does not name a password, token, or secret is ignored.",
  }),
  "detect-eval-with-expression": detector({
    classId: "injection", taxonomyId: "dynamic-code", precision: "high", risk: "high", cwe: ["CWE-94"],
    title: "Eval of a non-literal value",
    next: "Confirm this call does not run request data",
    defaultPattern: "eval",
    sinkPatterns: ["eval"],
    sanitizers: ["fixed function call"],
    confidenceBasis: "eval is called with a non-literal.",
    limitations: "Indirect calls through a variable are not named by this rule.",
  }),
  "detect-child-process": detector({
    classId: "injection", taxonomyId: "command-execution", precision: "high", risk: "high", cwe: ["CWE-78"],
    title: "Command execution",
    next: "Confirm the command is not built from request data",
    defaultPattern: "command",
    sinkPatterns: ["child_process.exec", "child_process import"],
    sanitizers: ["execFile with an argument array"],
    confidenceBasis: "A shell exec call or a child_process import is present.",
    limitations: "Argument injection, PATH hijacking, and shell dialect are the same finding.",
  }),
  "detect-non-literal-fs-filename": detector({
    classId: "path_file", taxonomyId: "untrusted-path", precision: "medium", risk: "medium", cwe: ["CWE-22"],
    title: "Filesystem path is not a literal",
    next: "Path is not a literal; no request input is visible in this call",
    defaultPattern: "path",
    sinkPatterns: ["filesystem call"],
    sanitizers: ["fixed path", "final path segment only"],
    confidenceBasis: "A filesystem API receives a non-literal path.",
    limitations: "Archive entry names that never reach a filesystem call in this function are missed.",
  }),
  "detect-non-literal-regexp": detector({
    classId: "resource_consumption", taxonomyId: "regex-from-input", precision: "medium", risk: "medium",
    cwe: ["CWE-1333", "CWE-400"],
    title: "Regular expression built from a non-literal",
    next: "Confirm this expression is a fixed pattern",
    defaultPattern: "regex",
    sinkPatterns: ["RegExp constructor"],
    sanitizers: ["literal pattern"],
    confidenceBasis: "new RegExp receives a non-literal.",
    limitations: "A nested literal pattern is not stored or classified as catastrophic.",
  }),
  gitleaks: detector({
    classId: "secrets", taxonomyId: "credential-in-source", precision: "high", risk: "critical", cwe: ["CWE-798"],
    title: "Credential pattern",
    next: "Remove the credential from the source and rotate it",
    languages: ["*"],
    evidenceType: "secret_pattern",
    collapse: false,
    defaultPattern: "credential",
    sourcePatterns: ["literal"],
    sinkPatterns: ["credential pattern"],
    sanitizers: ["secret removed and rotated"],
    confidenceBasis: "The text matches a credential pattern.",
    limitations: "Default, embedded, and cloud credentials are the same finding when the literal is in the scanned tree.",
  }),
  "trivy-critical": detector({
    classId: "security_config", taxonomyId: "insecure-configuration", precision: "high", risk: "critical", cwe: ["CWE-16"],
    title: "Critical configuration finding",
    next: "Review this configuration finding",
    languages: ["hcl"],
    evidenceType: "config",
    collapse: false,
    defaultPattern: "config",
    sinkPatterns: ["infrastructure configuration"],
    sanitizers: ["restricted configuration"],
    confidenceBasis: "Trivy reported a critical misconfiguration.",
    limitations: "Public storage, open networks, and permissive identity share this analyzer.",
  }),
  "trivy-other": detector({
    classId: "security_config", taxonomyId: "insecure-configuration", precision: "medium", risk: "medium", cwe: ["CWE-16"],
    title: "Configuration finding",
    next: "Review this configuration finding",
    languages: ["hcl"],
    evidenceType: "config",
    collapse: false,
    defaultPattern: "config",
    sinkPatterns: ["infrastructure configuration"],
    sanitizers: ["restricted configuration"],
    confidenceBasis: "Trivy reported a misconfiguration below critical.",
    limitations: "Public storage, open networks, and permissive identity share this analyzer.",
  }),
  "npm-audit": detector({
    classId: "supply_chain", taxonomyId: "dependency-risk", precision: "medium", risk: "medium", cwe: ["CWE-1395"],
    title: "Dependency advisory",
    next: "Review this dependency advisory",
    languages: ["json"],
    evidenceType: "advisory",
    collapse: false,
    defaultPattern: "advisory",
    patternNext: { "missing-lockfile": "Commit the lockfile that produced this install" },
    sinkPatterns: ["package.json", "package-lock.json"],
    sanitizers: ["patched dependency", "lockfile"],
    confidenceBasis: "npm audit reported an advisory, or package.json has no lockfile.",
    limitations: "Unpinned ranges, typosquatting, provenance, and CI trust are out of scope.",
  }),
  "js.query.nosql": detector({
    classId: "injection", taxonomyId: "query-built-from-input", precision: "high", risk: "high", cwe: ["CWE-943"],
    title: "Query object built with a Mongo operator from the request",
    next: "Confirm the query shape is fixed and the value is bound",
    defaultPattern: "nosql",
    sourcePatterns: ["request"],
    sinkPatterns: ["Mongo operator"],
    sanitizers: ["fixed query shape"],
    confidenceBasis: "A Mongo operator is copied from the request or concatenated into the query text.",
    limitations: "Operator, filter, aggregation, and database JavaScript share this finding.",
  }),
  "js.query.ldap": detector({
    classId: "injection", taxonomyId: "query-built-from-input", precision: "high", risk: "high", cwe: ["CWE-90"],
    title: "LDAP filter built by concatenation",
    next: "Confirm the filter is escaped for LDAP",
    defaultPattern: "ldap",
    sourcePatterns: ["request", "non-literal"],
    sinkPatterns: ["LDAP filter string"],
    sanitizers: ["escapeFilter"],
    confidenceBasis: "A filter-shaped string is concatenated with a non-literal.",
    limitations: "XPath and search syntax stay out until a sink API is named.",
  }),
  "js.ssrf.fetch": detector({
    classId: "ssrf_url", taxonomyId: "untrusted-url-fetch", precision: "high", risk: "high", cwe: ["CWE-918"],
    title: "Outbound request URL is not a literal",
    next: "Confirm the host is a fixed origin",
    defaultPattern: "fetch",
    sourcePatterns: ["non-literal", "Host header"],
    sinkPatterns: ["fetch", "http.get", "axios"],
    sanitizers: ["fixed origin"],
    confidenceBasis: "An HTTP client is called with a non-literal URL.",
    limitations: "Blind, metadata, rebinding, and redirect-following variants are not separated.",
  }),
  "js.control.char": detector({
    classId: "injection", taxonomyId: "control-char-injection", precision: "medium", risk: "medium",
    cwe: ["CWE-93", "CWE-117"],
    title: "Request data written into a header, log, message, or CSV row",
    next: "Confirm control characters are stripped before this write",
    defaultPattern: "header",
    sourcePatterns: ["request"],
    sinkPatterns: ["setHeader", "sendMail", "log", "writeCsv"],
    sanitizers: ["stripCrlf", "structured log", "CSV escape"],
    confidenceBasis: "Request data reaches a header, mail, log, or CSV call.",
    limitations: "Passwords, tokens, and req.body are reported by the sensitive-log rule instead.",
  }),
  "js.cookie.flags": detector({
    classId: "session_token", taxonomyId: "cookie-missing-flags", precision: "medium", risk: "medium",
    cwe: ["CWE-614", "CWE-1004"],
    title: "Cookie is set without httpOnly, secure, or sameSite",
    next: "Confirm this cookie sets httpOnly, secure, and sameSite",
    defaultPattern: "cookie",
    evidenceType: "missing_flag",
    sinkPatterns: ["res.cookie"],
    sanitizers: ["httpOnly", "secure", "sameSite"],
    confidenceBasis: "res.cookie is called with none of the three flags.",
    limitations: "Session fixation, idle timeout, logout, and concurrent sessions need a session store.",
  }),
  "js.jwt.verify": detector({
    classId: "authentication", taxonomyId: "jwt-verify-weak", precision: "high", risk: "high", cwe: ["CWE-347"],
    title: "JWT verification does not pin a signature algorithm",
    next: "Confirm verify allows one explicit algorithm",
    defaultPattern: "none",
    patternPrecision: { "missing-algorithms": "medium", none: "high", decode: "high" },
    sinkPatterns: ["jwt.verify", "jwt.decode"],
    sanitizers: ["algorithms allowlist"],
    confidenceBasis: "verify allows none, omits algorithms, or decode is used.",
    limitations: "Replay, refresh reuse, PKCE, OAuth state, OIDC nonce, and SAML need a protocol trace.",
  }),
  "js.tls.verify": detector({
    classId: "cryptography", taxonomyId: "tls-verification-disabled", precision: "high", risk: "high", cwe: ["CWE-295"],
    title: "TLS verification is disabled or negotiated down",
    next: "Confirm certificate and hostname checks stay on",
    defaultPattern: "tls",
    sinkPatterns: ["rejectUnauthorized", "minVersion", "secureProtocol", "NODE_TLS_REJECT_UNAUTHORIZED"],
    sanitizers: ["rejectUnauthorized true", "TLS 1.2 or newer"],
    confidenceBasis: "A known-bad TLS option is set in source.",
    limitations: "Protocol downgrade that depends on peer negotiation is not visible.",
  }),
  "js.field.privileged": detector({
    classId: "access_control", taxonomyId: "client-controlled-privileged-field", precision: "low", risk: "medium",
    cwe: ["CWE-915"],
    title: "Privileged field is copied from the request body",
    next: "Confirm the server assigns this field itself",
    defaultPattern: "role",
    evidenceType: "unsafe_call",
    sourcePatterns: ["req.body"],
    sinkPatterns: ["role", "isAdmin", "tenantId", "ownerId", "price", "quantity", "status", "merge"],
    sanitizers: ["server-assigned value"],
    confidenceBasis: "A privileged name is assigned from req.body, or the body is merged into an object.",
    limitations: "This is not proof that authorization is missing. IDOR and role checks need a policy.",
  }),
  "js.origin.trust": detector({
    classId: "security_config", taxonomyId: "untrusted-origin-trust", precision: "high", risk: "high",
    cwe: ["CWE-942", "CWE-346"],
    title: "Caller-supplied origin is trusted",
    next: "Confirm the origin is an allowlist and postMessage names a fixed origin",
    defaultPattern: "wildcard",
    patternPrecision: { wildcard: "high", reflected: "medium", postmessage: "high" },
    sinkPatterns: ["cors origin", "postMessage"],
    sanitizers: ["fixed origin"],
    confidenceBasis: "Credentials are combined with a wildcard or reflected origin, or postMessage targets * or a non-literal.",
    limitations: "Frame, CSP, and COOP headers are not inferred from their absence.",
  }),
  "js.browser.secret": detector({
    classId: "sensitive_data", taxonomyId: "browser-secret-storage", precision: "medium", risk: "medium", cwe: ["CWE-922"],
    title: "Secret stored in browser web storage",
    next: "Confirm this value is not a token or password",
    defaultPattern: "storage",
    sinkPatterns: ["localStorage.setItem", "sessionStorage.setItem"],
    sanitizers: ["memory held by the server session"],
    confidenceBasis: "setItem's arguments name a token, password, secret, session, or jwt.",
    limitations: "Platform keystores and mobile private files are out of scope.",
  }),
  "js.sensitive.log": detector({
    classId: "sensitive_data", taxonomyId: "sensitive-log", precision: "medium", risk: "medium", cwe: ["CWE-532"],
    title: "Password, token, or request body written to a log",
    next: "Confirm this log does not record a credential or the request body",
    defaultPattern: "log",
    sinkPatterns: ["log", "info", "warn", "error"],
    sanitizers: ["log the identifier, not the secret"],
    confidenceBasis: "A log call receives password, token, secret, authorization, or req.body.",
    limitations: "A line already reported as a credential pattern is not reported again.",
  }),
  "js.error.client": detector({
    classId: "controls_errors", taxonomyId: "error-detail-to-client", precision: "medium", risk: "medium", cwe: ["CWE-209"],
    title: "Error detail sent to the client",
    next: "Confirm the response uses a fixed message",
    defaultPattern: "stack",
    sinkPatterns: ["res.send", "res.json", "res.end"],
    sanitizers: ["fixed error message"],
    confidenceBasis: "err, err.stack, or err.message is passed to the response.",
    limitations: "PII classes are not inferred without a data inventory.",
  }),
  "js.template.render": detector({
    classId: "injection", taxonomyId: "template-render-untrusted", precision: "high", risk: "high", cwe: ["CWE-1336"],
    title: "Template source is not a literal",
    next: "Confirm the template source is a fixed file",
    defaultPattern: "template",
    sinkPatterns: ["ejs.render", "pug.render", "handlebars.compile", "nunjucks.render", "vm.Script"],
    sanitizers: ["literal template"],
    confidenceBasis: "A template engine compiles a non-literal source.",
    limitations: "Auto-escaped HTML sinks stay on the HTML rule.",
  }),
  "js.session.secret": detector({
    classId: "secrets", taxonomyId: "hardcoded-session-secret", precision: "high", risk: "high", cwe: ["CWE-798"],
    title: "Session secret is a string literal",
    next: "Move this secret out of source and rotate it",
    defaultPattern: "session",
    sinkPatterns: ["session secret literal"],
    sanitizers: ["environment variable", "secret store"],
    confidenceBasis: "session() is given a secret property whose value is a string literal.",
    limitations: "A secret copied from a variable is not resolved. Gitleaks remains a separate credential scan.",
  }),
  "js.auth.reset-token": detector({
    classId: "authentication", taxonomyId: "predictable-reset-token", precision: "high", risk: "high", cwe: ["CWE-640"],
    title: "Password reset token is a hash of the login",
    next: "Confirm the reset token is random and stored for that user",
    defaultPattern: "reset",
    sinkPatterns: ["md5 of login", "md5 of username"],
    sanitizers: ["random token", "stored expiry"],
    confidenceBasis: "A token comparison hashes the login or username from the request.",
    limitations: "The same call is not also reported as a weak hash. An ordinary timing comparison on that line stays.",
  }),
  "js.sensitive.response": detector({
    classId: "sensitive_data", taxonomyId: "sensitive-response", precision: "medium", risk: "medium", cwe: ["CWE-200"],
    title: "Full record sent in a JSON response",
    next: "Confirm the response lists only the fields the client needs",
    defaultPattern: "response",
    sinkPatterns: ["findAll", "find", "findOne", "res.json"],
    sanitizers: ["attributes list"],
    confidenceBasis: "A model query with no attributes list is sent with res.json or res.send in the same continuation.",
    limitations: "A render call is not a JSON response. The column names are not read from the model.",
  }),
  "js.orm.query-log": detector({
    classId: "sensitive_data", taxonomyId: "query-logging", precision: "medium", risk: "medium", cwe: ["CWE-532"],
    title: "Database client logs queries",
    next: "Confirm database logging is off",
    defaultPattern: "query-log",
    sinkPatterns: ["Sequelize constructor"],
    sanitizers: ["logging: false"],
    confidenceBasis: "new Sequelize is called without logging set to false.",
    limitations: "A logging flag inside a variable is not visible. Both the URL form and the options form are reported.",
  }),
  "js.authz.admin-route": detector({
    classId: "access_control", taxonomyId: "missing-authorization", precision: "medium", risk: "medium", cwe: ["CWE-862"],
    title: "Admin route has no admin check in this file",
    next: "Confirm the handler checks the caller's role",
    defaultPattern: "admin",
    sinkPatterns: ["admin route"],
    sanitizers: ["admin middleware", "role check in the handler"],
    confidenceBasis: "The route path contains /admin and no handler in this call reads a role or is named as an admin check.",
    limitations: "A check inside a handler defined in another file is not visible.",
  }),
  "js.authz.object-id": detector({
    classId: "access_control", taxonomyId: "client-controlled-object-id", precision: "medium", risk: "medium", cwe: ["CWE-639"],
    title: "Record id taken from the request and saved",
    next: "Confirm this id is the caller's",
    defaultPattern: "object-id",
    sinkPatterns: ["find by request id", "save"],
    sanitizers: ["session id"],
    confidenceBasis: "A query uses an id from the request and the loaded record is written in that continuation.",
    limitations: "A lookup that only renders is not a write. An ownership check in another function is not visible. Repeated copies of the same sink in one file are one finding that lists each line.",
  }),
  "js.error.uncaught": detector({
    classId: "controls_errors", taxonomyId: "uncaught-error", precision: "medium", risk: "medium", cwe: ["CWE-209"],
    title: "Uncaught error can reach the client",
    next: "Confirm a handler sends a fixed message",
    defaultPattern: "uncaught",
    sinkPatterns: ["eval outside try"],
    sanitizers: ["try"],
    confidenceBasis: "eval is called with a non-literal and the call is not inside try.",
    limitations: "The code-injection finding on the same call stays. The framework's default error page is not in this file.",
  }),
  "js.error.middleware": detector({
    classId: "controls_errors", taxonomyId: "missing-error-handler", precision: "medium", risk: "medium", cwe: ["CWE-209"],
    title: "Express app has no error handler",
    next: "Confirm an error handler sends a fixed message",
    defaultPattern: "middleware",
    sinkPatterns: ["express()"],
    sanitizers: ["four-argument middleware"],
    confidenceBasis: "The file calls express() and never passes a function with four parameters to use().",
    limitations: "An error handler registered in another file is not visible.",
  }),
  "js.config.powered-by": detector({
    classId: "security_config", taxonomyId: "framework-fingerprint", precision: "medium", risk: "medium", cwe: ["CWE-200"],
    title: "X-Powered-By header left on",
    next: "Confirm the framework name header is disabled",
    defaultPattern: "powered-by",
    sinkPatterns: ["express()"],
    sanitizers: ["disable x-powered-by"],
    confidenceBasis: "The file calls express() and does not disable x-powered-by.",
    limitations: "A disable call in another file is not visible.",
  }),
  "js.xss.template": detector({
    classId: "xss", taxonomyId: "unescaped-template", precision: "high", risk: "high", cwe: ["CWE-79"],
    title: "Unescaped template output",
    next: "Confirm this output is escaped",
    languages: ["ejs"],
    defaultPattern: "template",
    sinkPatterns: ["unescaped template tag"],
    sanitizers: ["escaped output", "include"],
    confidenceBasis: "An EJS unescaped tag prints a value.",
    limitations: "A tag whose body starts with include is a partial, not this finding. Escaped tags are not reported. Repeated copies of the same sink in one file are one finding that lists each line.",
  }),
  "js.supply.advisory": detector({
    classId: "supply_chain", taxonomyId: "known-vulnerable-dependency", precision: "high", risk: "high", cwe: ["CWE-1395"],
    title: "Known vulnerable dependency",
    next: "Upgrade this package off the vulnerable pin",
    languages: ["json"],
    defaultPattern: "advisory",
    sinkPatterns: ["package.json pin"],
    sanitizers: ["upgraded version"],
    confidenceBasis: "package.json pins a version named in the simulator advisory list.",
    limitations: "The list is the checked-in advisory set, not a live feed. A range specifier is not the pinned release.",
    collapse: false,
  }),
  "js.audit.auth-log": detector({
    classId: "security_config", taxonomyId: "missing-audit-log", precision: "medium", risk: "medium", cwe: ["CWE-778"],
    title: "Failed sign-in is not logged",
    next: "Confirm failed sign-in is written to the audit log",
    defaultPattern: "auth",
    sinkPatterns: ["done(null, false)"],
    sanitizers: ["log call"],
    confidenceBasis: "done(null, false) runs in a function that has no log call.",
    limitations: "A log written in the caller, or under another name, is not visible.",
  }),
  "js.csrf.missing": detector({
    classId: "session_token", taxonomyId: "missing-csrf", precision: "medium", risk: "medium", cwe: ["CWE-352"],
    title: "State-changing route has no CSRF check",
    next: "Confirm a CSRF check is mounted for this route",
    defaultPattern: "csrf",
    sinkPatterns: ["post", "put", "patch", "delete"],
    sanitizers: ["csrf middleware"],
    confidenceBasis: "The file registers a state-changing route and never mentions csrf or csurf.",
    limitations: "A check mounted in another file is not visible. Every state-changing route in the file is reported.",
  }),
  "likeness.candidate": detector({
    classId: "injection", taxonomyId: "similar-function", precision: "low", risk: "medium", cwe: ["CWE-89"],
    title: "Similar to a vulnerable corpus sample",
    next: "Compare this function with the corpus sample",
    collapse: false,
    defaultPattern: "clone",
    evidenceType: "unsafe_call",
    sinkPatterns: ["corpus likeness"],
    sanitizers: ["patched twin"],
    confidenceBasis: "The function is close to a vulnerable sample and far from its patched twin.",
    limitations: "Likeness comments. It does not assign an exploit mechanism.",
  }),
};

const ESLINT_RULES = {
  "local/string-concat-query": "js.sqli.string-concat",
  "local/sql-literal": "js.sql.literal",
  "local/dangerous-html": "js.xss.dangerous-html",
  "local/member-eval": "js.eval.member",
  "local/unserialize": "js.deser.unserialize",
  "local/request-redirect": "js.redirect.request",
  "local/xml-entities": "js.xml.entities",
  "local/md5-token": "js.crypto.md5-token",
  "local/nosql-operator": "js.query.nosql",
  "local/ldap-filter": "js.query.ldap",
  "local/url-fetch": "js.ssrf.fetch",
  "local/control-char": "js.control.char",
  "local/cookie-flags": "js.cookie.flags",
  "local/jwt-verify": "js.jwt.verify",
  "local/tls-verify": "js.tls.verify",
  "local/privileged-field": "js.field.privileged",
  "local/origin-trust": "js.origin.trust",
  "local/browser-secret": "js.browser.secret",
  "local/sensitive-log": "js.sensitive.log",
  "local/error-to-client": "js.error.client",
  "local/template-render": "js.template.render",
  "local/session-secret": "js.session.secret",
  "local/reset-token": "js.auth.reset-token",
  "local/sensitive-response": "js.sensitive.response",
  "local/orm-query-log": "js.orm.query-log",
  "local/admin-route": "js.authz.admin-route",
  "local/object-id": "js.authz.object-id",
  "local/uncaught-sink": "js.error.uncaught",
  "local/error-middleware": "js.error.middleware",
  "local/powered-by": "js.config.powered-by",
  "local/auth-log": "js.audit.auth-log",
  "local/csrf": "js.csrf.missing",
  "security/detect-eval-with-expression": "detect-eval-with-expression",
  "security/detect-child-process": "detect-child-process",
  "security/detect-non-literal-fs-filename": "detect-non-literal-fs-filename",
  "security/detect-non-literal-regexp": "detect-non-literal-regexp",
};

export function stableRuleId(eslintRuleId) {
  return ESLINT_RULES[eslintRuleId] || null;
}

const BAND = { high: 3, medium: 2, low: 1 };

export function precisionFor(spec, pattern) {
  if (pattern && spec.patternPrecision && spec.patternPrecision[pattern]) return spec.patternPrecision[pattern];
  return spec.precision;
}

export function choosePattern(spec, patterns) {
  const unique = [...new Set(patterns.filter(Boolean))];
  if (!unique.length) return spec.defaultPattern || "";
  return unique.sort((left, right) => {
    const rank = (BAND[precisionFor(spec, right)] || 0) - (BAND[precisionFor(spec, left)] || 0);
    if (rank) return rank;
    return left.localeCompare(right);
  })[0];
}

export const FINDING_LABELS = {
  "js.sqli.string-concat": {
    subclass: "SQL injection",
    finding: "SQL injection via concatenated query",
    problem: "A value that is not a fixed string is joined into the SQL. This line does not show request data. If a caller controls that value, they can change the query and read or modify rows.",
    problemRequest: "Request data is joined into the SQL. A caller can change the query and read or modify rows.",
  },
  "js.sql.literal": {
    subclass: "SQL injection",
    finding: "SQL query literal",
    problem: "A SQL statement is present as a fixed string. This line does not show outside data joined into it. Risk appears only if a later change adds that data.",
  },
  "js.xss.dangerous-html": {
    subclass: "Cross-site scripting",
    finding: "Cross-site scripting via HTML sink",
    problem: "A value that is not a fixed string is written as HTML. This line does not show request data. If a user controls the value, the browser can run it in another user's session.",
    problemRequest: "Request data is written as HTML. A caller can run script in the browser of whoever views the page.",
  },
  "js.eval.member": {
    subclass: "Code injection",
    finding: "Code injection via eval",
    problem: "eval or Function is called with a value that is not a fixed string. This line does not show request data. If a caller controls the value, they can run JavaScript on the server.",
    problemRequest: "eval or Function runs request data. A caller can run JavaScript on the server.",
  },
  "js.deser.unserialize": {
    subclass: "Insecure deserialization",
    patternFinding: {
      unserialize: "Insecure deserialization via unserialize",
      yaml: "Insecure YAML load",
    },
    patternProblem: {
      unserialize: "unserialize rebuilds objects from a payload. If that payload is untrusted, constructing the objects can run code the application did not call.",
      yaml: "yaml.load accepts a document that can name objects. If the document is untrusted, the parser can build objects the application did not expect.",
    },
    patternProblemRequest: {
      unserialize: "An uploaded payload is passed to unserialize. If the bytes are hostile, constructing the objects can run code the application did not call.",
      yaml: "An uploaded document is passed to yaml.load. If the document is hostile, the parser can build objects the application did not expect.",
    },
  },
  "js.redirect.request": {
    subclass: "Open redirect",
    patternFinding: {
      redirect: "Open redirect via request URL",
      host: "Open redirect via Host header",
    },
    patternProblem: {
      redirect: "The redirect target comes from the request. A caller can send the user to a site they control.",
      host: "The redirect URL is built from the Host header. A forged host can send the user to another site.",
    },
  },
  "js.xml.entities": {
    subclass: "XML external entity",
    finding: "XML external entity expansion",
    problem: "The parser substitutes entities in the document it is given. A hostile document can read local files or expand until the process runs out of memory.",
    problemRequest: "An uploaded document is parsed with entity substitution on. A hostile document can read local files or expand until the process runs out of memory.",
  },
  "js.crypto.md5-token": {
    subclass: "Cryptographic weakness",
    patternSubclass: {
      "weak-hash": "Weak hash",
      "insecure-random": "Insecure randomness",
      "static-iv": "Static initialization vector",
      "unsafe-compare": "Timing-unsafe comparison",
    },
    patternFinding: {
      "weak-hash": "Weak hash used for a security value",
      "insecure-random": "Security token drawn from Math.random",
      "static-iv": "Cipher initialized with a static IV",
      "unsafe-compare": "Secret compared with ordinary equality",
    },
    patternProblem: {
      "weak-hash": "MD5 or SHA-1 is used where a password or token needs a slow hash. Someone can guess the input much faster than with a modern password hash.",
      "insecure-random": "A token is drawn from Math.random, which is predictable. Someone who observes the output can guess later values.",
      "static-iv": "The cipher reuses one initialization vector. Repeating it can reveal patterns across messages encrypted with the same key.",
      "unsafe-compare": "A password, token, or secret is compared with ordinary equality. The comparison can reveal how much of the secret matched.",
    },
  },
  "detect-eval-with-expression": {
    subclass: "Code injection",
    finding: "Code injection via eval",
    problem: "eval is called with a value that is not a fixed string. This line does not show request data. If a caller controls the value, they can run JavaScript on the server.",
    problemRequest: "eval runs request data. A caller can run JavaScript on the server.",
  },
  "detect-child-process": {
    subclass: "Command injection",
    finding: "OS command injection via shell exec",
    problem: "A shell command is present. This line does not show request data. If a caller can influence the command, they can run operating-system commands on the host.",
    problemRequest: "A shell command is built with request data. A caller can run operating-system commands on the host.",
  },
  "detect-non-literal-fs-filename": {
    subclass: "Local file inclusion",
    finding: "Local file inclusion via dynamic path",
    problem: "A filesystem call uses a path that is not a fixed string. This line does not show request data. If a caller can influence the path, they can read or overwrite files outside the intended directory.",
  },
  "detect-non-literal-regexp": {
    subclass: "Regular expression denial of service",
    finding: "Regular expression built from input",
    problem: "new RegExp receives a value that is not a fixed string. This line does not show request data. If a caller supplies the pattern, matching can consume the process until it stops responding.",
    problemRequest: "new RegExp receives request data. A caller can supply a pattern that consumes the process until it stops responding.",
  },
  gitleaks: {
    subclass: "Hardcoded credential",
    finding: "Credential in source",
    problem: "The text matches a credential. Anyone who can read the repository can use it until it is removed and rotated.",
  },
  "trivy-critical": {
    subclass: "Critical misconfiguration",
    finding: "Critical configuration finding",
    problem: "Trivy marked this configuration critical. As configured, the resource is exposed or permitted beyond the intended boundary.",
  },
  "trivy-other": {
    subclass: "Misconfiguration",
    finding: "Configuration finding",
    problem: "Trivy reported a misconfiguration below critical. As configured, the resource is weaker than the intended boundary.",
  },
  "npm-audit": {
    subclass: "Vulnerable dependency",
    finding: "Dependency advisory",
    problem: "npm audit reported a known vulnerability in a dependency. The install stays affected until the package is upgraded or removed.",
    patternSubclass: { "missing-lockfile": "Unpinned dependency" },
    patternFinding: { "missing-lockfile": "Dependency manifest has no lockfile" },
    patternProblem: {
      "missing-lockfile": "package.json has no lockfile. A later install can resolve different versions than the ones that were reviewed, including a vulnerable release.",
    },
  },
  "js.query.nosql": {
    subclass: "NoSQL injection",
    finding: "NoSQL injection via Mongo operator",
    problem: "A Mongo operator is taken from the request or joined into the query. A caller can change which documents match.",
  },
  "js.query.ldap": {
    subclass: "LDAP injection",
    finding: "LDAP injection via concatenated filter",
    problem: "A value that is not a fixed string is joined into an LDAP filter. If a caller controls that value, they can change which entries match.",
    problemRequest: "Request data is joined into an LDAP filter. A caller can change which entries match.",
  },
  "js.ssrf.fetch": {
    subclass: "Server-side request forgery",
    finding: "Server-side request forgery via dynamic URL",
    problem: "An HTTP client is called with a URL that is not a fixed string. This line does not show request data. If a caller chooses the URL, the server will request hosts it can reach, including internal ones.",
    problemRequest: "An HTTP client is called with a URL from the request. A caller can make the server request internal hosts it can reach.",
  },
  "js.control.char": {
    subclass: "Control-character injection",
    patternSubclass: {
      header: "HTTP header injection",
      log: "Log injection",
      mail: "Email header injection",
      csv: "CSV injection",
    },
    patternFinding: {
      header: "HTTP header injection",
      log: "Log injection",
      mail: "Email header injection",
      csv: "CSV injection",
    },
    patternProblem: {
      header: "Request data is written into a response header. A newline in that value can add headers the application did not set.",
      log: "Request data is written into a log line. A newline in that value can forge later log entries.",
      mail: "Request data is written into a mail message. A newline in that value can add mail headers.",
      csv: "Request data is written into a CSV row. A value that starts with a formula prefix can be interpreted as a formula when the file is opened in a spreadsheet.",
    },
  },
  "js.cookie.flags": {
    subclass: "Insecure cookie",
    finding: "Cookie missing httpOnly, secure, and sameSite",
    problem: "The cookie is set without httpOnly, secure, and sameSite. Script on the page can read it, and the browser may send it on an insecure or cross-site request.",
  },
  "js.jwt.verify": {
    subclass: "Broken JWT verification",
    patternSubclass: {
      none: "JWT none algorithm",
      "missing-algorithms": "JWT algorithm not pinned",
      decode: "Unverified JWT",
    },
    patternFinding: {
      none: "JWT verification accepts the none algorithm",
      "missing-algorithms": "JWT verification does not pin an algorithm",
      decode: "JWT decoded without signature verification",
    },
    patternProblem: {
      none: "Verification allows the none algorithm. A caller can forge a token that the server accepts with no signature.",
      "missing-algorithms": "verify does not pin an algorithm. A caller can present a token under a weaker algorithm the library still accepts.",
      decode: "The token is decoded and the signature is not checked. A caller can supply any payload and the server will trust it.",
    },
  },
  "js.tls.verify": {
    subclass: "TLS verification disabled",
    finding: "TLS certificate checks turned off",
    problem: "Certificate or protocol checks are disabled. A network position can impersonate the host the application meant to reach.",
  },
  "js.field.privileged": {
    subclass: "Mass assignment",
    finding: "Privileged field copied from the request",
    problem: "A privileged field is copied from the request body. A caller can set a role, price, owner, or status the server was supposed to assign.",
    patternFinding: {
      role: "Client-controlled role",
      "is-admin": "Client-controlled admin flag",
      "tenant-id": "Client-controlled tenant id",
      "owner-id": "Client-controlled owner id",
      price: "Client-controlled price",
      quantity: "Client-controlled quantity",
      status: "Client-controlled status",
      merge: "Request body merged into an object",
    },
    patternProblem: {
      merge: "The request body is merged into an object. A caller can set role, price, or other fields the server was supposed to assign. This line does not show which field is honored.",
    },
  },
  "js.origin.trust": {
    subclass: "Origin trust",
    patternSubclass: {
      wildcard: "CORS misconfiguration",
      reflected: "CORS misconfiguration",
      postmessage: "Cross-window messaging",
    },
    patternFinding: {
      wildcard: "CORS wildcard origin with credentials",
      reflected: "CORS reflects the request origin",
      postmessage: "postMessage without a fixed origin",
    },
    patternProblem: {
      wildcard: "Any site is allowed to make credentialed browser requests. A hostile page can act as the signed-in user.",
      reflected: "The request origin is reflected and credentials are allowed. A hostile site can send authenticated requests.",
      postmessage: "postMessage targets every origin, or an origin that is not fixed. Any window that receives the message can read it.",
    },
  },
  "js.browser.secret": {
    subclass: "Secret in web storage",
    finding: "Secret stored in browser web storage",
    problem: "A token or password is written to localStorage or sessionStorage. Any script on the page can read it.",
  },
  "js.sensitive.log": {
    subclass: "Sensitive data in logs",
    finding: "Password, token, or request body written to a log",
    problem: "A password, token, or the request body is written to a log. Anyone who can read the logs can reuse that secret.",
  },
  "js.error.client": {
    subclass: "Information disclosure",
    finding: "Error detail sent to the client",
    problem: "The response includes an error object, message, or stack. The client learns internal paths, queries, or library details.",
  },
  "js.template.render": {
    subclass: "Server-side template injection",
    finding: "Server-side template injection via dynamic template",
    problem: "A template engine compiles a source that is not a fixed string. This line does not show request data. If a caller supplies the template, the server runs it.",
    problemRequest: "A template engine compiles request data. A caller can run code on the server.",
  },
  "js.session.secret": {
    subclass: "Hardcoded session secret",
    finding: "Session secret is a source literal",
    problem: "The session secret is a fixed string in source. Anyone who can read it can forge a session cookie.",
  },
  "js.auth.reset-token": {
    subclass: "Predictable reset token",
    finding: "Password reset token is a hash of the login",
    problem: "The reset token is the hash of the login. Someone who knows the login can compute the token and reset that account.",
    problemRequest: "The reset token is the hash of the login from the request. A caller who knows the login can compute the token and reset that account.",
  },
  "js.sensitive.response": {
    subclass: "Sensitive data in response",
    finding: "Full record sent in a JSON response",
    problem: "The query does not limit columns, and the result is sent as JSON. A user record includes the password hash.",
  },
  "js.orm.query-log": {
    subclass: "Query logging",
    finding: "Database client logs queries",
    problem: "The database client is created without logging turned off. Queries, including ones that contain passwords or tokens, are written to the log.",
  },
  "js.authz.admin-route": {
    subclass: "Missing authorization",
    finding: "Admin route has no admin check in this file",
    problem: "This admin route does not check a role in this file. A signed-in caller who is not an admin can call it if the handler does not check either.",
  },
  "js.authz.object-id": {
    subclass: "Insecure direct object reference",
    finding: "Record id taken from the request and saved",
    problem: "The record is loaded by an id from the request and then saved. A caller can change another person's row by submitting that id.",
  },
  "js.error.uncaught": {
    subclass: "Information disclosure",
    finding: "Uncaught error can reach the client",
    problem: "A call that can throw is not inside try. The framework error handler can send the stack when the process is not in production.",
    problemRequest: "Request data is passed to a call that can throw, and this call is not inside try. The framework error handler can send the stack when the process is not in production.",
  },
  "js.error.middleware": {
    subclass: "Information disclosure",
    finding: "Express app has no error handler",
    problem: "This file starts Express and does not register an error-handling middleware. The default handler sends the stack when NODE_ENV is not production.",
  },
  "js.config.powered-by": {
    subclass: "Framework fingerprint",
    finding: "X-Powered-By header left on",
    problem: "This file starts Express and does not disable X-Powered-By. Responses advertise the framework.",
  },
  "js.xss.template": {
    subclass: "Cross-site scripting",
    finding: "Unescaped template output",
    problem: "This template prints a value with an unescaped tag. If that value is user-controlled, the browser runs it in the viewer's session.",
  },
  "js.supply.advisory": {
    subclass: "Vulnerable dependency",
    finding: "Known vulnerable dependency",
    problem: "This pinned version is on the simulator advisory list. The release is known to be vulnerable.",
  },
  "js.audit.auth-log": {
    subclass: "Missing audit log",
    finding: "Failed sign-in is not logged",
    problem: "Authentication failure returns without a log call in this function. A repeated guessing attempt leaves no record.",
  },
  "js.csrf.missing": {
    subclass: "Cross-site request forgery",
    finding: "State-changing route has no CSRF check",
    problem: "This file registers a state-changing route and does not mention a CSRF check. Another site can submit the form as the signed-in user.",
  },
  "likeness.candidate": {
    subclass: "Vulnerable clone",
    finding: "Similar to a known-vulnerable function",
    problem: "This function is close to a known-vulnerable sample and far from its patched copy. The match is a lead. It does not show that the same flaw is reachable.",
  },
};

function uniqueText(values) {
  return [...new Set(values.filter(Boolean))];
}

function problemText(labels, pattern, showsRequest) {
  if (showsRequest && labels.patternProblemRequest && labels.patternProblemRequest[pattern]) {
    return labels.patternProblemRequest[pattern];
  }
  if (labels.patternProblem && labels.patternProblem[pattern]) return labels.patternProblem[pattern];
  if (showsRequest && labels.problemRequest) return labels.problemRequest;
  return labels.problem || "";
}

export function describeFinding(spec, ctx = {}) {
  const labels = FINDING_LABELS[ctx.ruleId] || {};
  const patterns = uniqueText([...(ctx.patterns || []), ctx.pattern]);
  const primary = ctx.pattern || patterns[0] || spec.defaultPattern || "";
  const ordered = uniqueText([primary, ...patterns]);
  const showsRequest = /\b(req|request)\b/.test(ctx.sourceLine || "");
  let subclass = "";
  let finding = "";
  let problem = "";
  if (!ordered.length) {
    subclass = labels.subclass || spec.taxonomyId || "";
    finding = labels.finding || spec.title || "";
    problem = labels.problem || "";
  } else {
    subclass = uniqueText(ordered.map((item) => labels.patternSubclass?.[item] || labels.subclass)).join(", ");
    finding = uniqueText(ordered.map((item) => labels.patternFinding?.[item] || labels.finding)).join("; ");
    problem = uniqueText(ordered.map((item) => problemText(labels, item, showsRequest))).join(" ");
  }
  if (!subclass) subclass = labels.subclass || spec.taxonomyId || "";
  if (!finding) finding = labels.finding || spec.title || "";
  if (!problem) problem = (showsRequest && labels.problemRequest) || labels.problem || "";
  if (ctx.ruleId === "detect-child-process" && /require\(/.test(ctx.message || "")) {
    subclass = "Command injection";
    finding = "Child process module imported";
    problem = "This file imports child_process. The import does not show a command built from a request. If a later call passes request data to a shell, that data can run commands on the host.";
  }
  if (ctx.ruleId === "detect-non-literal-fs-filename" && showsRequest) {
    subclass = "Local file inclusion";
    finding = "Local file inclusion via request path";
    problem = "A filesystem call uses a path taken from the request. A caller can point it outside the intended directory and read or overwrite files.";
  }
  if (ctx.ruleId === "likeness.candidate" && ctx.family) {
    finding = `Similar to vulnerable sample ${ctx.family}`;
  }
  if (["npm-audit", "trivy-critical", "trivy-other", "js.supply.advisory"].includes(ctx.ruleId) && ctx.message && primary !== "missing-lockfile") {
    finding = ctx.message;
  }
  return {
    classLabel: CLASS_LABELS[spec.classId] || spec.classId || "",
    subclass,
    finding,
    problem,
  };
}
