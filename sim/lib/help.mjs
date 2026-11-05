import { FINDING_LABELS, RULES, describeFinding } from "./policy.mjs";

function variantPatterns(ruleId, spec) {
  const labels = FINDING_LABELS[ruleId] || {};
  const keys = [...new Set([
    ...Object.keys(labels.patternSubclass || {}),
    ...Object.keys(labels.patternFinding || {}),
    ...Object.keys(labels.patternProblem || {}),
  ])];
  return keys.length ? keys : [spec.defaultPattern || ""];
}

function checks() {
  const groups = new Map();
  for (const [ruleId, spec] of Object.entries(RULES)) {
    for (const pattern of variantPatterns(ruleId, spec)) {
      const described = describeFinding(spec, { ruleId, pattern, patterns: [pattern] });
      const key = `${described.classLabel}\n${described.subclass}`;
      if (!groups.has(key)) groups.set(key, []);
      const items = groups.get(key);
      if (!items.some((item) => item.finding === described.finding && item.ruleId === ruleId)) {
        items.push({ ruleId, finding: described.finding });
      }
    }
  }
  const lines = [];
  for (const [key, items] of groups) {
    const [classLabel, subclass] = key.split("\n");
    lines.push(`  ${classLabel} / ${subclass}`);
    for (const item of items) lines.push(`    ${item.finding} (${item.ruleId})`);
  }
  return lines.join("\n");
}

export function helpText() {
  return `Code review simulator

A scan prints JSON to the terminal and writes sim/out/<repoName>_report.html.
Open that file in a browser. The next scan of the same repository archives the
previous file under sim/out/archive/<repoName>/ with the date and time in the
name. The current report lists those earlier versions at the bottom.
The first scan also starts a local service on 127.0.0.1:47321 so the risk
dropdown can save. It stays running and only accepts rating updates for this
database. Run node report-server.mjs if that service is not running.
node scan.mjs --dashboard writes sim/out/dashboard.html from the latest scan
of each current report. It does not scan. Open http://127.0.0.1:47321/ for
that page.

Commands, from the sim directory:

  node scan.mjs --event <fixtures/events/file.json> --as <role>
  node scan.mjs --source <path> [--data-class public|internal|restricted] --as <role>
  node scan.mjs --dashboard
  node adjudicate.mjs --finding <id> --label <false_positive|true_positive|accepted_risk> --as <developer|appsec>
  node waive.mjs --fingerprint <id> --reason <text> --hours <n> --as appsec
  node promote-signature.mjs --code-unit <id> --as appsec
  npm run replay

--help on any of these commands prints this guide.
replay wipes the local database and checks the built-in scenarios. It prints "replay ok".

Roles:

  developer   findings, class, subclass, pull status, and location
  appsec      also redacted secret previews and rule detail
  auditor     findings, without secret previews

Pull status:

  internal or public    high findings are comments
  restricted            a high-precision, high-risk finding blocks
  secret                a high-precision credential pattern blocks
  critical IaC          a critical Trivy finding blocks, when Trivy is installed
  likeness              a corpus match comments. It does not block
  waiver                AppSec can suppress a block until it expires. The finding stays

Report header:

  Deployment is Failed or Passed. Hover a header label to read what that field means.
  Data class is public, internal, or restricted.

Report columns:

  Risk, Class, Subclass, Finding, Problem, Location, Code, Confidence (0–1), Next step, Pull Status
  Risk is a dropdown: informational, low, medium, high, or critical.
  Choosing a rating saves it in sim/out/review.sqlite. Informational is stored as info.
  The same finding keeps that rating on a later scan. Pull status stays on the rule rating.
  Confidence shows the band and the score, for example high (0.90). Scores run from 0 to 1.
  Pull status is block, comment, or clear.
  Subclass names the vulnerability type, such as SQL injection, command injection,
  cross-site scripting, or local file inclusion. Finding is the specific name.
  A similar-finding line under Finding opens a comparison table. This finding's code is on the top row and the matched code is below it. The matched location starts with the repository name.
  Problem says what could go wrong, including when request data is not shown.
  Each column can be sorted and filtered in the report.

What a scan checks:

${checks()}

Hits of the same rule merge only when their source ranges overlap.
Another hit of that rule in the same function stays its own finding.
A SQL literal is dropped when concatenation already covers that statement,
and it is suppressed when the function matches sim/corpus/approved/.
Paths matching *.min.js, public/assets/, vendor/, or dist/ are not linted.
npm audit runs when package-lock.json is present. A package.json without a
lockfile is a supply-chain finding. Gitleaks and Trivy run only when those
commands are on PATH. If they are missing, that analyzer is marked skipped.

What a scan does not check:

  Authorization enforced only inside a handler in another file, session lifetime,
  OAuth and SAML, business rules, races, and memory safety. Those need a policy,
  a session store, or another language. TypeScript, Python, Go, and Java files
  are copied into the snapshot and are not rule-checked. Arrow functions and
  class methods are not compared with the corpus.

Cache and corpus:

  The same checkout at the same commit is a cache hit, and the analyzers do not
  run again. A new commit or a promoted signature scans again. Checked-in likeness
  starts at loadOrder. Each finished scan stores risky functions and clean
  functions, and the next commit or repository is compared with that library.
  A false positive removes the risky sample. Promotion is AppSec-only and writes
  a new corpus version.

Limits for --source:

  2,000 files and 20 MB. A file over 100 KB is skipped. A larger tree stops with
  a cap error. Raise external_max_files and external_max_total_bytes in
  sim/policy.json, or scan a subdirectory.
`;
}
