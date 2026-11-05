import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { extractFunctions } from "./lib/extract.mjs";
import { normalizeTokens, similarity, sketchOf } from "./lib/minhash.mjs";
import { analyzerCallCount, runScan, setRiskRating } from "./lib/pipeline.mjs";
import { decideGate } from "./lib/policy.mjs";
import { helpText } from "./lib/help.mjs";
import { openDb } from "./lib/db.mjs";
import { corpusDir, simRoot } from "./lib/paths.mjs";
import { reportPathFor } from "./lib/report-files.mjs";

if (process.argv.includes("--help")) {
  process.stdout.write(helpText());
  process.exit(0);
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function run(args) {
  const result = spawnSync(process.execPath, ["--disable-warning=ExperimentalWarning", ...args], {
    cwd: simRoot,
    encoding: "utf8",
  });
  if (result.status !== 0) {
    throw new Error(`${args.join(" ")} failed (${result.status})\n${result.stdout}\n${result.stderr}`);
  }
  const line = result.stdout.trim().split(/\n/).filter(Boolean).pop();
  return JSON.parse(line);
}

function runExpectFail(args) {
  const result = spawnSync(process.execPath, ["--disable-warning=ExperimentalWarning", ...args], {
    cwd: simRoot,
    encoding: "utf8",
  });
  assert(result.status !== 0, `${args.join(" ")} should have failed`);
  return result;
}

function sketchFile(file) {
  const source = fs.readFileSync(file, "utf8");
  const fn = extractFunctions(source)[0];
  return sketchOf(normalizeTokens(fn.body));
}

function resetDir(dir) {
  if (fs.existsSync(dir)) {
    for (const entry of fs.readdirSync(dir)) {
      fs.rmSync(path.join(dir, entry), { recursive: true, force: true });
    }
  }
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch (error) {
    if (!fs.existsSync(dir) || fs.readdirSync(dir).length) throw error;
  }
}

resetDir(path.join(simRoot, "out"));
resetDir(path.join(simRoot, "snapshots"));
resetDir(path.join(corpusDir, "promoted"));

const policy = JSON.parse(fs.readFileSync(path.join(simRoot, "policy.json"), "utf8"));
assert(decideGate({
  classId: "injection", precision: "high", risk: "high", dataClass: "restricted",
}, policy) === "block", "restricted high-precision finding should block");
assert(decideGate({
  classId: "injection", precision: "high", risk: "high", dataClass: "internal",
}, policy) === "comment", "internal high finding should comment");
assert(decideGate({
  classId: "injection", precision: "high", risk: "high", dataClass: "restricted", system2Only: true,
}, policy) === "comment", "system 2 alone should not block");
assert(decideGate({
  classId: "secrets", precision: "high", risk: "critical", dataClass: "public",
}, policy) === "block", "secrets should block");

const vulnerable = sketchFile(path.join(corpusDir, "vulnerable", "loadOrder.js"));
const patched = sketchFile(path.join(corpusDir, "patched", "loadOrder.js"));
const clone = sketchFile(path.join(simRoot, "fixtures", "repos", "clone-order", "src", "fetchOrder.js"));
const clean = sketchFile(path.join(simRoot, "fixtures", "repos", "clean-order", "src", "loadOrder.js"));
const cloneToVulnerable = similarity(clone, vulnerable);
const cloneToPatched = similarity(clone, patched);
const cleanToApproved = similarity(clean, patched);
assert(cloneToVulnerable >= 0.8, `clone should match vulnerable sample, got ${cloneToVulnerable}`);
assert(cloneToPatched < 0.8, `clone should stay below the patched twin, got ${cloneToPatched}`);
assert(cleanToApproved >= 0.8, `clean sample should match the approved control, got ${cleanToApproved}`);

const cleanScan = run(["scan.mjs", "--event", "fixtures/events/clean.json", "--as", "developer"]);
assert(cleanScan.check === "success", "clean scan should pass");
assert(cleanScan.system2 === "not_run", "system 2 stub should record not_run");
assert(cleanScan.findings.some((finding) => finding.gate === "clear" && finding.disposition === "suppressed"), "approved control should suppress the noisy rule");
const callsAfterClean = analyzerCallCount();
const cleanAgain = run(["scan.mjs", "--event", "fixtures/events/clean.json", "--as", "developer"]);
assert(cleanAgain.cache_hit === true, "repeated event should be a cache hit");
assert(cleanAgain.analyzers_called === false, "cache hit should not call analyzers");
assert(analyzerCallCount() === callsAfterClean, "analyzer call count should stay put on a cache hit");

const likeness = run(["scan.mjs", "--event", "fixtures/events/likeness-internal.json", "--as", "developer"]);
assert(likeness.check === "success", "internal likeness scan should not block");
assert(likeness.findings.some((finding) => finding.factors.likeness_vulnerable >= 0.8 && finding.factors.likeness_patched_twin < 0.8), "likeness scan should record both scores");
assert(!likeness.findings.some((finding) => finding.gate === "block"), "internal service should not block");

const restricted = run(["scan.mjs", "--event", "fixtures/events/restricted-block.json", "--as", "appsec"]);
assert(restricted.check === "failure", "restricted high-precision rule should block");
assert(restricted.findings.some((finding) => finding.gate === "block" && finding.factors.rule_id === "js.sqli.string-concat"), "block should come from the query rule");
assert(restricted.findings.some((finding) => finding.evidence.function_name === "fetchOrder" && String(finding.evidence.source_line).includes("SELECT")), "block finding should name the function and show the line");
assert(restricted.findings.some((finding) => finding.evidence.next_step === "Confirm this value reaches a query call"), "block finding should say what to confirm");
assert(!restricted.findings.some((finding) => finding.factors.rule_id === "js.sql.literal"), "SQL literal should be dropped when concatenation covers the statement");
assert(restricted.findings.every((finding) => finding.system2 === "not_run"), "system 2 should not clear findings");

const prompt = run(["scan.mjs", "--event", "fixtures/events/prompt-boundary.json", "--as", "developer"]);
assert(prompt.findings.some((finding) => finding.factors.rule_id === "js.sqli.string-concat"), "inline disable and instruction comment should not remove the finding");
assert(prompt.findings.some((finding) => finding.factors.untrusted_comment_ignored === true), "untrusted comment should be recorded");
assert(prompt.findings.every((finding) => finding.system2 === "not_run"), "stub should ignore the instruction");

const sinks = run(["scan.mjs", "--event", "fixtures/events/sinks.json", "--as", "developer"]);
const sinkRules = new Set(sinks.findings.map((finding) => finding.factors.rule_id));
assert(sinkRules.has("detect-eval-with-expression"), "eval sink should be flagged");
assert(sinkRules.has("detect-child-process"), "child process sink should be flagged");
assert(sinkRules.has("js.xss.dangerous-html"), "html sink should be flagged");
assert(sinkRules.has("js.eval.member"), "member eval should be flagged");
assert(sinkRules.has("js.deser.unserialize"), "unserialize should be flagged");
assert(sinkRules.has("js.redirect.request"), "request redirect should be flagged");
assert(sinkRules.has("js.xml.entities"), "xml entity substitution should be flagged");
assert(sinkRules.has("js.crypto.md5-token"), "md5 token comparison should be flagged");
const tokenCheck = sinks.findings.filter((finding) => finding.evidence.function_name === "checkToken");
assert(tokenCheck.some((finding) => finding.factors.rule_id === "js.crypto.md5-token" && (finding.factors.patterns || []).includes("unsafe-compare")), "the token comparison should stay");
assert(tokenCheck.some((finding) => finding.factors.rule_id === "js.auth.reset-token"), "a hash of the login should be a reset token");
assert(!tokenCheck.some((finding) => (finding.factors.patterns || []).includes("weak-hash")), "a reset token should not also be a weak hash");
assert(!sinks.findings.some((finding) => String(finding.evidence.path).includes("noise.min.js")), "vendor path should not be linted");
const eslintStatus = sinks.analyzers.find((analyzer) => analyzer.name === "eslint");
assert(eslintStatus.status.includes("skipped") && eslintStatus.status.includes("vendor"), "eslint should record skipped vendor files");

const target = likeness.findings.find((finding) => finding.factors.rule_id === "js.sqli.string-concat");
const adjudication = run(["adjudicate.mjs", "--finding", target.id, "--label", "false_positive", "--as", "developer"]);
assert(adjudication.finding_still_present === true, "adjudication should keep the finding");
assert(adjudication.signature_created === false, "false positive should not create a signature");
assert(adjudication.disposition === "false_positive", "disposition should record the label");

const blocking = restricted.findings.find((finding) => finding.gate === "block");
const waiver = run(["waive.mjs", "--fingerprint", blocking.fingerprint, "--reason", "timed exception", "--hours", "24", "--as", "appsec"]);
assert(waiver.findings_retained > 0, "waiver should keep finding history");
const waived = run(["scan.mjs", "--event", "fixtures/events/restricted-rescan.json", "--as", "developer"]);
assert(waived.cache_hit === true, "waiver recheck should reuse the scan");
assert(waived.analyzers_called === false, "waiver recheck should not call analyzers");
assert(waived.findings.some((finding) => finding.fingerprint === blocking.fingerprint), "waived finding should stay visible");
assert(!waived.findings.some((finding) => finding.fingerprint === blocking.fingerprint && finding.gate === "block"), "active waiver should suppress the block");

runExpectFail(["promote-signature.mjs", "--code-unit", target.code_unit_id, "--as", "developer"]);
const promoted = run(["promote-signature.mjs", "--code-unit", target.code_unit_id, "--as", "appsec"]);
assert(promoted.corpus_digest !== likeness.corpus_digest, "promotion should publish a new corpus digest");

const rescan = run(["scan.mjs", "--event", "fixtures/events/likeness-rescan.json", "--as", "appsec"]);
assert(rescan.cache_hit === false, "new corpus digest should miss the cache");
assert(rescan.matches.some((match) => match.provenance === "appsec_promotion" && match.similarity >= 0.8), "later clone should match the promoted signature");

const secret = run(["scan.mjs", "--event", "fixtures/events/secret.json", "--as", "developer"]);
assert(!JSON.stringify(secret).includes("AKIAIOSFODNN7EXAMPLE"), "developer output should not contain the credential");
const secretAnalyzer = secret.analyzers.find((analyzer) => analyzer.name === "gitleaks");
assert(secretAnalyzer.status === "ok" || secretAnalyzer.status === "skipped", "gitleaks should run or skip");
run(["scan.mjs", "--event", "fixtures/events/iac.json", "--as", "developer"]);
const report = fs.readFileSync(reportPathFor("iac-sample"), "utf8");
assert(fs.existsSync(reportPathFor("iac-sample")), "scan should write iac-sample_report.html");
assert(!fs.existsSync(path.join(simRoot, "out", "report.html")), "scan should not write report.html");
assert(report.includes("Code review simulation"), "report should be written");
assert(report.includes("Report archive"), "report should include an archive of earlier versions");
assert(report.includes('aria-label="Risk rating"') || report.includes("No findings."), "report should offer a risk rating when it has findings");
assert(report.includes("Problem"), "report should state what could go wrong");
assert(report.includes('data-sort="subclass"'), "each findings column should sort");
assert(report.includes('data-filter="problem"'), "each findings column should filter");
assert(!report.includes("What we found"), "report should not use the old title column");
assert(report.includes("Next step"), "report should include a next step");
assert(!report.includes("<th>Likeness</th>"), "likeness should not be a default column");
assert(!report.includes("<th>Differing tokens</th>"), "token diffs should not be a default column");
assert(!report.includes("AKIAIOSFODNN7EXAMPLE"), "report should not contain the credential");

const unlocked = run(["scan.mjs", "--event", "fixtures/events/unlocked.json", "--as", "developer"]);
assert(unlocked.findings.every((finding) => finding.factors.rule_id === "npm-audit"), "a missing lockfile should not invent other findings");
assert(unlocked.findings.filter((finding) => finding.factors.pattern === "missing-lockfile").length === 1, "missing lockfile should be one supply-chain finding");

const cluster = run(["scan.mjs", "--event", "fixtures/events/cluster.json", "--as", "developer"]);
const htmlSinks = cluster.findings.filter((finding) => finding.factors.rule_id === "js.xss.dangerous-html");
assert(htmlSinks.length === 1, `repeated innerHTML should be one finding, got ${htmlSinks.length}`);
assert(htmlSinks[0].evidence.sites.map((site) => site.line).join(",") === "40,41,42", "html sink sites should be lines 40-42");
const templateCopies = cluster.findings.filter((finding) => finding.factors.rule_id === "js.xss.template");
assert(templateCopies.length === 1, `repeated template tags should be one finding, got ${templateCopies.length}`);
assert(templateCopies[0].evidence.sites.map((site) => site.line).join(",") === "49,50,51,52,53", "template sites should be lines 49-53");
const idor = cluster.findings.filter((finding) => finding.factors.rule_id === "js.authz.object-id");
assert(idor.length === 1, `repeated object id lookups should be one finding, got ${idor.length}`);
const idorNames = idor[0].evidence.sites.map((site) => site.function_name).sort();
assert(JSON.stringify(idorNames) === JSON.stringify(["modifyProductSubmit", "userEditSubmit"]), `object id sites should name both writes, got ${idorNames.join(", ")}`);
assert(!idor[0].evidence.sites.some((site) => site.function_name === "modifyProduct"), "a lookup that only renders should stay out");
assert(cluster.findings.length === 3, `cluster fixture should be 3 findings, got ${cluster.findings.map((finding) => finding.factors.rule_id).join(", ")}`);
const clusterReport = fs.readFileSync(reportPathFor("cluster"), "utf8");
assert(clusterReport.includes("adminusers.ejs:40-42"), "report should show the contiguous html range");
assert(clusterReport.includes("products.ejs:49-53"), "report should show the contiguous template range");
assert(clusterReport.includes("modifyProductSubmit"), "report should list the product write");
assert(clusterReport.includes("userEditSubmit"), "report should list the user write");
assert(!clusterReport.includes("gap-between-copies"), "split sites should not span the code between them");

const triage = run(["scan.mjs", "--event", "fixtures/events/triage.json", "--as", "developer"]);
const secretBlocks = triage.findings.filter((finding) => finding.gate === "block");
assert(secretBlocks.length === 1 && secretBlocks[0].factors.rule_id === "js.session.secret", "internal triage should block only the hardcoded session secret");
assert(triage.check === "failure", "the session secret should fail the internal check");
assert(triage.findings.filter((finding) => finding.factors.rule_id !== "js.session.secret").every((finding) => finding.gate === "comment"), "other internal triage findings should comment");
const expectedTriage = [
  ["queryTemplate", "js.sqli.string-concat", "query-built-from-input", [["sql"], ["sql"]]],
  ["queryNosql", "js.query.nosql", "query-built-from-input", [["nosql"]]],
  ["queryLdap", "js.query.ldap", "query-built-from-input", [["ldap"]]],
  ["fetchUrl", "js.ssrf.fetch", "untrusted-url-fetch", [["fetch"]]],
  ["writeHeader", "js.control.char", "control-char-injection", [["header"], ["log"], ["mail"], ["csv"]]],
  ["setSessionCookie", "js.cookie.flags", "cookie-missing-flags", [["cookie"]]],
  ["acceptJwt", "js.jwt.verify", "jwt-verify-weak", [["decode"], ["missing-algorithms"], ["none"]]],
  ["trustTls", "js.tls.verify", "tls-verification-disabled", [["tls"]]],
  ["copyRole", "js.field.privileged", "client-controlled-privileged-field", [["role"]]],
  ["openCors", "js.origin.trust", "untrusted-origin-trust", [["postmessage"], ["wildcard"]]],
  ["storeToken", "js.browser.secret", "browser-secret-storage", [["storage"]]],
  ["logPassword", "js.sensitive.log", "sensitive-log", [["log"]]],
  ["sendError", "js.error.client", "error-detail-to-client", [["stack"]]],
  ["renderTemplate", "js.template.render", "template-render-untrusted", [["template"]]],
  ["loadYaml", "js.deser.unserialize", "unsafe-deserialize", [["yaml"]]],
  ["innerHtml", "js.xss.dangerous-html", "unsafe-html-sink", [["html"], ["html"]]],
  ["hostRedirect", "js.redirect.request", "untrusted-redirect", [["host"]]],
  ["mixedCrypto", "js.crypto.md5-token", "crypto-misuse", [["insecure-random"], ["weak-hash"], ["static-iv"]]],
  ["compareSecrets", "js.crypto.md5-token", "crypto-misuse", [["unsafe-compare"], ["unsafe-compare"]]],
  ["compareSecrets", "js.auth.reset-token", "predictable-reset-token", [["reset"]]],
  ["buildRegex", "detect-non-literal-regexp", "regex-from-input", [["regex"]]],
  ["openSession", "js.session.secret", "hardcoded-session-secret", [["session"]]],
  ["forgeReset", "js.auth.reset-token", "predictable-reset-token", [["reset"]]],
  ["forgeReset", "js.crypto.md5-token", "crypto-misuse", [["unsafe-compare"]]],
  ["publishUsers", "js.sensitive.response", "sensitive-response", [["response"]]],
  ["connectDb", "js.orm.query-log", "query-logging", [["query-log"], ["query-log"]]],
  ["mountAdmin", "js.authz.admin-route", "missing-authorization", [["admin"]]],
  ["saveUser", "js.authz.object-id", "client-controlled-object-id", [["object-id"]]],
  ["runEquation", "js.eval.member", "dynamic-code", [["eval"]]],
  ["runEquation", "js.error.uncaught", "uncaught-error", [["uncaught"]]],
  ["bootApp", "js.error.middleware", "missing-error-handler", [["middleware"]]],
  ["bootApp", "js.config.powered-by", "framework-fingerprint", [["powered-by"]]],
  ["failedLogin", "js.audit.auth-log", "missing-audit-log", [["auth"]]],
  ["exportRoutes", "js.csrf.missing", "missing-csrf", [["csrf"]]],
];
for (const [name, ruleId, taxonomyId, groups] of expectedTriage) {
  const matches = triage.findings
    .filter((finding) => finding.evidence.function_name === name && finding.factors.rule_id === ruleId)
    .sort((left, right) => (left.evidence.line - right.evidence.line) || ((left.evidence.column || 0) - (right.evidence.column || 0)));
  assert(matches.length === groups.length, `${name} ${ruleId} should produce ${groups.length} findings, got ${matches.length}`);
  matches.forEach((finding, index) => {
    assert(finding.factors.rule_id === ruleId, `${name} should use ${ruleId}`);
    assert(finding.factors.taxonomy_id === taxonomyId, `${name} should use ${taxonomyId}`);
    const got = [...(finding.factors.patterns || [])].sort();
    assert(JSON.stringify(got) === JSON.stringify([...groups[index]].sort()), `${name} site ${index + 1} patterns should be ${groups[index].join(", ")}, got ${got.join(", ")}`);
  });
}
const safeFindings = triage.findings.filter((finding) => String(finding.evidence.function_name).startsWith("safe"));
assert(safeFindings.every((finding) => finding.factors.rule_id === "likeness.candidate" && finding.gate === "comment"), "sanitized functions should not be rule findings");
assert(!triage.findings.some((finding) => finding.evidence.function_name === "guardedEquation" && finding.factors.rule_id === "js.error.uncaught"), "try should cover the throwing eval");
const equation = triage.findings.find((finding) => finding.evidence.function_name === "runEquation" && finding.factors.rule_id === "js.eval.member");
const equationNames = (equation.evidence.sites || []).map((site) => site.function_name).sort();
assert(JSON.stringify(equationNames) === JSON.stringify(["guardedEquation", "runEquation"]), "identical eval calls in one file should be one finding");
assert(!triage.findings.some((finding) => finding.evidence.function_name === "compareSecrets" && (finding.factors.patterns || []).includes("weak-hash")), "a reset token should not also be a weak hash");
const templateFindings = triage.findings.filter((finding) => String(finding.evidence.path).endsWith("views/profile.ejs"));
assert(templateFindings.filter((finding) => finding.factors.rule_id === "js.xss.template").length === 1, "one unescaped template tag should be reported");
assert(templateFindings.filter((finding) => finding.factors.rule_id === "js.xss.dangerous-html").length === 1, "one innerHTML assignment should be reported");
assert(templateFindings.some((finding) => String(finding.evidence.source_line).includes("<%-")), "the unescaped tag should be the template finding");
assert(!templateFindings.some((finding) => /include\(/.test(String(finding.evidence.source_line)) || String(finding.evidence.source_line).includes("textContent")), "includes and text assignment should not be findings");
assert(triage.findings.some((finding) => finding.factors.rule_id === "js.supply.advisory" && finding.evidence.path === "package.json" && String(finding.evidence.source_line).includes("mathjs")), "mathjs 3.10.1 should be an advisory");
assert(!triage.findings.some((finding) => finding.factors.pattern === "missing-lockfile"), "a lockfile should cover the manifest check");
assert(restricted.findings.some((finding) => finding.factors.rule_id === "js.sqli.string-concat" && finding.factors.taxonomy_id === "query-built-from-input" && finding.factors.pattern === "sql"), "existing SQL finding should keep one taxonomy");

const triageReport = fs.readFileSync(reportPathFor("triage"), "utf8");
assert(triageReport.includes("SQL injection"), "report subclass should name SQL injection");
assert(triageReport.includes("NoSQL injection"), "report subclass should name NoSQL injection");
assert(triageReport.includes("LDAP injection"), "report subclass should name LDAP injection");
assert(triageReport.includes("Cross-site scripting"), "report subclass should name cross-site scripting");
assert(triageReport.includes("change the query and read or modify rows"), "report should state the SQL impact");
assert(triageReport.includes(">Class<"), "report should show the class column");
assert(triageReport.includes(">Subclass<"), "report should show the subclass column");
assert(triageReport.includes(">Problem<"), "report should state what could go wrong");
assert(!triageReport.includes("query-built-from-input"), "subclass column should not show the generic taxonomy id");
assert(!triageReport.includes("What we found"), "report should not use the old title column");

const observedRisk = run(["scan.mjs", "--event", "fixtures/events/seen-risk.json", "--as", "developer"]);
const observedFinding = observedRisk.findings.find((finding) => finding.factors.rule_id === "js.sqli.string-concat" && finding.evidence.function_name === "billShipment");
assert(observedFinding, "seen-risk scan should flag the shipment query");
const observedClone = run(["scan.mjs", "--event", "fixtures/events/seen-clone.json", "--as", "developer"]);
const cloneFinding = observedClone.findings.find((finding) => finding.evidence.function_name === "invoiceParcel" && finding.factors.rule_id === "js.sqli.string-concat");
assert(cloneFinding, "seen-clone scan should flag the renamed shipment query");
assert(cloneFinding.factors.likeness_vulnerable >= 0.8, `clone likeness should match the stored finding, got ${cloneFinding.factors.likeness_vulnerable}`);
assert(cloneFinding.factors.likeness_patched_twin < 0.8, `patched twin should stay below the secure library, got ${cloneFinding.factors.likeness_patched_twin}`);
assert(cloneFinding.factors.likeness_provenance === "scan_observed", "clone should match a scan-observed signature");
assert(cloneFinding.factors.likeness_function === "billShipment", "clone should name the stored function");
assert(cloneFinding.factors.likeness_repo === "seen-risk", "clone should name the stored repository");
const observedReport = fs.readFileSync(reportPathFor("seen-clone"), "utf8");
assert(observedReport.includes("Similar to billShipment in seen-risk"), "report should name the stored finding");
assert(observedReport.includes('class="compare"'), "similar finding should open in a comparison table");
assert(observedReport.includes("parcelCode"), "report should show the matched finding code");
assert(observedReport.includes("seen-risk · src/billShipment.js · billShipment"), "similar location should name the repository");
const clearedObserved = run(["adjudicate.mjs", "--finding", observedFinding.id, "--label", "false_positive", "--as", "developer"]);
assert(clearedObserved.signature_created === false, "false positive should not promote a signature");
const cloneAgain = run(["scan.mjs", "--event", "fixtures/events/seen-clone-again.json", "--as", "developer"]);
assert(cloneAgain.cache_hit === false, "a new commit should scan against the updated library");
const cloneAgainFinding = cloneAgain.findings.find((finding) => finding.evidence.function_name === "invoiceParcel" && finding.factors.rule_id === "js.sqli.string-concat");
assert(cloneAgainFinding, "the renamed query should still be flagged by the rule");
assert(cloneAgainFinding.factors.likeness_function !== "billShipment", "false positive should drop the stored function");
assert(!(cloneAgainFinding.factors.likeness_provenance === "scan_observed" && cloneAgainFinding.factors.likeness_vulnerable >= 0.8), `observed match should be gone, got ${cloneAgainFinding.factors.likeness_vulnerable} from ${cloneAgainFinding.factors.likeness_function}`);

const seenArchive = path.join(simRoot, "out", "archive", "seen-clone");
assert(fs.existsSync(seenArchive), "a second scan should archive the previous seen-clone report");
const seenArchiveNames = fs.readdirSync(seenArchive);
assert(seenArchiveNames.some((name) => /^seen-clone_report_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}\.html$/.test(name)), "archived report name should include the date and time");
const seenReport = fs.readFileSync(reportPathFor("seen-clone"), "utf8");
assert(seenReport.includes("Report archive"), "current report should list the archive");
assert(seenReport.lastIndexOf("Report archive") > seenReport.lastIndexOf("Pull status"), "archive should sit at the bottom");
assert(/seen-clone_report\.html · \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC/.test(seenReport), "archive entry should show the date and time");

const ratingTarget = triage.findings.find((finding) => finding.risk_rating === "high" && finding.gate === "comment");
assert(ratingTarget, "triage should have a high comment finding to rerate");
const savedRating = setRiskRating({ findingId: ratingTarget.id, riskRating: "informational", role: "developer" });
assert(savedRating.risk_rating === "info", "informational should be stored as info");
const ratingDb = openDb();
const stored = ratingDb.prepare("SELECT risk_rating, gate FROM finding WHERE id = ?").get(ratingTarget.id);
const override = ratingDb.prepare("SELECT risk_rating FROM risk_override WHERE fingerprint = ?").get(ratingTarget.fingerprint);
ratingDb.close();
assert(stored.risk_rating === "info", "the finding row should store info");
assert(stored.gate === ratingTarget.gate, "changing the rating should leave the pull status alone");
assert(override.risk_rating === "info", "the consolidated rating should be saved");
const ratedReport = fs.readFileSync(reportPathFor("triage"), "utf8");
const ratedAt = ratedReport.indexOf(`data-finding="${ratingTarget.id}"`);
assert(ratedAt >= 0, "the report should still include the rerated finding");
assert(ratedReport.slice(ratedAt, ratedAt + 700).includes('value="informational" selected'), "the dropdown should show informational");

const triageEvent = JSON.parse(fs.readFileSync(path.join(simRoot, "fixtures", "events", "triage.json"), "utf8"));
const triageAgain = await runScan({
  event: { ...triageEvent, delivery_id: "evt-triage-rating", commit_sha: "triage222" },
  role: "developer",
});
const kept = triageAgain.findings.find((finding) => finding.fingerprint === ratingTarget.fingerprint);
assert(kept, "the later scan should still report the rerated finding");
assert(kept.risk_rating === "info", "a later scan should keep the saved rating");
assert(kept.gate === ratingTarget.gate, "a later scan should keep the original pull status");

process.stdout.write("replay ok\n");
