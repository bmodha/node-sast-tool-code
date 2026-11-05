import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createHash, randomUUID } from "node:crypto";
import { openDb } from "./db.mjs";
import { advisoriesPath, analyzersPath, corpusDir, eslintConfigPath, localRulesPath, outDir, policyPath, simRoot } from "./paths.mjs";
import { archivePreviousReport, listReportArchive, reportFileName, reportPathFor, reportServerOrigin, reportToken } from "./report-files.mjs";
import { differingTokens, normalizeTokens, similarity, sketchOf } from "./minhash.mjs";
import { extractFunctions } from "./extract.mjs";
import { CLASS_LABELS, CWE, RULES, checkFromFindings, choosePattern, decideGate, describeFinding, precisionFor } from "./policy.mjs";
import { runAdvisories, runEslint, runGitleaks, runNpmAudit, runTemplates, runTrivy } from "./analyzers.mjs";
import { review, sawUntrustedInstruction } from "./system2.mjs";
import { writeDashboard } from "./dashboard.mjs";
import { renderReport } from "./report.mjs";
import { drain } from "./queue.mjs";
import { safeDetail, scrub } from "./redact.mjs";

const ROLES = new Set(["developer", "appsec", "auditor"]);
const CALLS = path.join(outDir, "analyzer-calls.txt");

export function loadPolicy() {
  return JSON.parse(fs.readFileSync(policyPath, "utf8"));
}

export function analyzerCallCount() {
  if (!fs.existsSync(CALLS)) return 0;
  return Number(fs.readFileSync(CALLS, "utf8"));
}

function sha256(text) {
  return createHash("sha256").update(text).digest("hex");
}

function round(value) {
  return Math.round(value * 1000) / 1000;
}

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", "coverage", ".next", "vendor"]);

function walk(dir) {
  if (!fs.existsSync(dir)) return [];
  const files = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (SKIP_DIRS.has(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) files.push(...walk(full));
    else files.push(full);
  }
  return files;
}

function corpusItems() {
  const items = [];
  const groups = [
    ["vulnerable", "vulnerable"],
    ["patched", "patched_twin"],
    ["approved", "approved_control"],
  ];
  for (const [folder, kind] of groups) {
    const dir = path.join(corpusDir, folder);
    if (!fs.existsSync(dir)) continue;
    for (const file of fs.readdirSync(dir)) {
      if (!file.endsWith(".js")) continue;
      const source = fs.readFileSync(path.join(dir, file), "utf8");
      const fn = extractFunctions(source)[0];
      const body = fn ? fn.body : source;
      const tokens = normalizeTokens(body);
      items.push({
        featureRef: `${folder}/${file}`,
        kind,
        classId: "injection",
        family: path.basename(file, ".js"),
        qualifiedName: fn ? fn.name : path.basename(file, ".js"),
        provenance: "checked_in",
        tokens,
        sketch: sketchOf(tokens),
      });
    }
  }
  const promoted = path.join(corpusDir, "promoted");
  if (fs.existsSync(promoted)) {
    for (const file of fs.readdirSync(promoted)) {
      if (!file.endsWith(".json")) continue;
      const meta = JSON.parse(fs.readFileSync(path.join(promoted, file), "utf8"));
      const source = fs.readFileSync(path.join(promoted, meta.source_file), "utf8");
      const tokens = normalizeTokens(source);
      items.push({
        featureRef: `promoted/${file}`,
        kind: meta.kind,
        classId: meta.class_id,
        family: meta.family,
        qualifiedName: meta.qualified_name,
        provenance: meta.provenance,
        tokens,
        sketch: sketchOf(tokens),
      });
    }
  }
  return items;
}

function syncCorpus(db) {
  const version = db.prepare("SELECT version FROM corpus_meta WHERE id = 1").get().version;
  const items = corpusItems();
  const seen = new Set(items.map((item) => item.featureRef));
  const upsert = db.prepare(`INSERT INTO signature
    (feature_ref, id, kind, class_id, corpus_version, sketch, family, provenance, qualified_name)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(feature_ref) DO UPDATE SET
      kind = excluded.kind,
      class_id = excluded.class_id,
      corpus_version = excluded.corpus_version,
      sketch = excluded.sketch,
      family = excluded.family,
      provenance = excluded.provenance,
      qualified_name = excluded.qualified_name`);
  for (const item of items) {
    const existing = db.prepare("SELECT id FROM signature WHERE feature_ref = ?").get(item.featureRef);
    upsert.run(
      item.featureRef,
      existing?.id || randomUUID(),
      item.kind,
      item.classId,
      version,
      JSON.stringify(item.sketch),
      item.family,
      item.provenance,
      item.qualifiedName,
    );
  }
  const remove = db.prepare("DELETE FROM signature WHERE feature_ref = ?");
  for (const row of db.prepare("SELECT feature_ref, provenance FROM signature").all()) {
    if (row.provenance === "scan_observed") continue;
    if (!seen.has(row.feature_ref)) remove.run(row.feature_ref);
  }
  const digest = sha256(JSON.stringify({
    version,
    items: items
      .map((item) => ({ featureRef: item.featureRef, kind: item.kind, sketch: item.sketch }))
      .sort((a, b) => a.featureRef.localeCompare(b.featureRef)),
  }));
  db.prepare("UPDATE corpus_meta SET digest = ? WHERE id = 1").run(digest);
  const signatures = db.prepare("SELECT * FROM signature").all().map((row) => ({
    ...row,
    sketch: JSON.parse(row.sketch),
    tokens: tokensForSignature(row, items),
  }));
  return { version, digest, signatures };
}

function tokensForSignature(row, items) {
  const item = items.find((entry) => entry.featureRef === row.feature_ref);
  if (item) return item.tokens;
  if (!row.normalized) return [];
  try {
    const parsed = JSON.parse(row.normalized);
    if (Array.isArray(parsed)) return parsed;
  } catch {
    /* Older rows stored a space-joined token string. */
  }
  return String(row.normalized).split(" ");
}

function copySnapshot(sourceDir, sha, files) {
  const target = path.join(simRoot, "snapshots", sha);
  fs.rmSync(target, { recursive: true, force: true });
  fs.mkdirSync(target, { recursive: true });
  for (const file of files) {
    const relative = path.relative(sourceDir, file);
    const dest = path.join(target, relative);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.copyFileSync(file, dest);
  }
  return target;
}

function bumpAnalyzers() {
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(CALLS, String(analyzerCallCount() + 1));
}

function waiverActive(db, fingerprint) {
  return db.prepare("SELECT expires_at FROM waiver WHERE fingerprint = ?").all(fingerprint)
    .some((row) => Date.parse(row.expires_at) > Date.now());
}

function publicFinding(row, role) {
  const evidence = JSON.parse(row.evidence);
  if (role !== "appsec") {
    delete evidence.secretPreview;
    delete evidence.secretHash;
  }
  return {
    id: row.id,
    code_unit_id: row.code_unit_id,
    class_id: row.class_id,
    risk_rating: row.risk_rating,
    gate: row.gate,
    disposition: row.disposition,
    fingerprint: row.fingerprint,
    system2: row.system2,
    factors: JSON.parse(row.factors),
    evidence,
  };
}

function capSnippet(text) {
  const trimmed = scrub(String(text || "").trim());
  if (trimmed.length > 200) return `${trimmed.slice(0, 200)}…`;
  return trimmed;
}

function located(...parts) {
  return parts.filter(Boolean).join(" · ");
}

function corpusSample(family) {
  const name = String(family || "");
  if (!name) return null;
  for (const folder of ["vulnerable", "patched", "approved"]) {
    const file = path.join(corpusDir, folder, `${name}.js`);
    if (!fs.existsSync(file)) continue;
    const source = fs.readFileSync(file, "utf8");
    const fn = extractFunctions(source)[0];
    const functionName = fn ? fn.name : name;
    return {
      finding: functionName,
      where: `${folder}/${name}.js · ${functionName}`,
      code: capSnippet(fn ? fn.body : source),
    };
  }
  const promoted = path.join(corpusDir, "promoted");
  if (!fs.existsSync(promoted)) return null;
  for (const file of fs.readdirSync(promoted)) {
    if (!file.endsWith(".json")) continue;
    const meta = JSON.parse(fs.readFileSync(path.join(promoted, file), "utf8"));
    if (meta.family !== name && meta.qualified_name !== name) continue;
    const sourceFile = path.join(promoted, meta.source_file);
    if (!fs.existsSync(sourceFile)) continue;
    const source = fs.readFileSync(sourceFile, "utf8");
    const fn = extractFunctions(source).find((item) => item.name === meta.qualified_name) || extractFunctions(source)[0];
    const functionName = fn ? fn.name : (meta.qualified_name || name);
    return {
      finding: functionName,
      where: `promoted/${meta.source_file} · ${functionName}`,
      code: capSnippet(fn ? fn.body : source),
    };
  }
  return null;
}

function observedSample(db, factors) {
  const rows = db.prepare(`SELECT f.evidence, f.risk_rating, f.class_id
    FROM finding f
    JOIN code_unit cu ON cu.id = f.code_unit_id
    JOIN scan sc ON sc.id = f.scan_id
    JOIN repo r ON r.id = sc.repo_id
    WHERE r.name = ? AND cu.qualified_name = ? AND f.disposition = 'open'
    ORDER BY sc.created_at DESC, f.rowid DESC`).all(factors.likeness_repo || "", factors.likeness_function || "");
  const chosen = rows.find((row) => row.class_id === factors.likeness_class) || rows[0];
  if (!chosen) return null;
  const evidence = JSON.parse(chosen.evidence);
  const functionName = evidence.function_name || factors.likeness_function || "";
  const place = evidence.path || "";
  return {
    finding: evidence.finding_name || evidence.title || functionName,
    classLabel: evidence.class_label || CLASS_LABELS[chosen.class_id] || chosen.class_id || "",
    risk: chosen.risk_rating || factors.likeness_risk || "",
    where: located(factors.likeness_repo, place, functionName),
    code: capSnippet(evidence.source_line || ""),
  };
}

function similarSample(db, factors) {
  if (!factors.likeness_candidate) return null;
  const classLabel = CLASS_LABELS[factors.likeness_class] || factors.likeness_class || "";
  const risk = factors.likeness_risk || "";
  if (factors.likeness_provenance === "scan_observed") {
    return observedSample(db, factors) || {
      finding: factors.likeness_function || "",
      classLabel,
      risk,
      where: located(factors.likeness_repo, factors.likeness_function),
      code: "",
    };
  }
  const sample = corpusSample(factors.likeness_family || factors.likeness_function);
  return {
    finding: sample?.finding || factors.likeness_family || factors.likeness_function || "",
    classLabel,
    risk,
    where: located(factors.likeness_repo, sample?.where),
    code: sample?.code || "",
  };
}

function withSimilar(db, rows) {
  return rows.map((row) => {
    const factors = JSON.parse(row.factors || "{}");
    const similar = similarSample(db, factors);
    if (!similar) return row;
    return { ...row, factors: JSON.stringify({ ...factors, similar }) };
  });
}

function reportPayload(db, scanRow, role, extras) {
  const renderedFindings = db.prepare("SELECT * FROM finding WHERE scan_id = ? ORDER BY class_id").all(scanRow.id);
  const analyzers = JSON.parse(scanRow.analyzers_json || "[]");
  const check = checkFromFindings(renderedFindings);
  const dataClass = db.prepare(`SELECT s.data_class AS data_class
    FROM scan sc
    JOIN repo r ON r.id = sc.repo_id
    JOIN service s ON s.id = r.service_id
    WHERE sc.id = ?`).get(scanRow.id)?.data_class || "";
  return {
    payload: {
      role,
      scan: {
        check,
        check_reason: explainCheck(check, renderedFindings, dataClass),
        data_class: dataClass,
        cache_hit: extras.cacheHit,
        system2: "not_run",
        corpus_digest: scanRow.corpus_digest,
        commit_sha: scanRow.commit_sha,
        created_at: scanRow.created_at || "",
        repo_name: scanRow.repo_name || "",
        report_file: reportFileName(scanRow.repo_name || ""),
      },
      findings: withSimilar(db, renderedFindings),
      analyzers,
    },
    check,
    analyzers,
    renderedFindings,
  };
}

function rememberReportView(db, scanId, role, cacheHit) {
  const value = cacheHit === true ? 1 : cacheHit === false ? 0 : null;
  if (value === null) {
    db.prepare("UPDATE scan SET report_role = ? WHERE id = ?").run(role, scanId);
    return;
  }
  db.prepare("UPDATE scan SET report_role = ?, report_cache_hit = ? WHERE id = ?").run(role, value, scanId);
}

function writeReport(db, scanRow, role, extras, options = {}) {
  const repoName = db.prepare("SELECT name FROM repo WHERE id = ?").get(scanRow.repo_id)?.name || "";
  const namedRow = { ...scanRow, repo_name: repoName };
  const current = reportPayload(db, namedRow, role, extras);
  if (options.archivePrevious !== false) archivePreviousReport(repoName);
  const archive = listReportArchive(repoName);
  fs.mkdirSync(outDir, { recursive: true });
  const reportFile = reportPathFor(repoName);
  fs.writeFileSync(reportFile, renderReport({
    ...current.payload,
    archive,
    ratingUrl: `${reportServerOrigin()}/risk`,
    ratingToken: reportToken(),
  }));
  rememberReportView(db, scanRow.id, role, extras.cacheHit);
  writeDashboard(db);
  const { renderedFindings, analyzers, check } = current;
  if (options.auditView !== false) {
    db.prepare("INSERT INTO audit_event (id, actor_role, action, detail) VALUES (?, ?, 'view_report', ?)").run(
      randomUUID(),
      role,
      JSON.stringify(safeDetail({ scan_id: scanRow.id, role })),
    );
  }
  const matches = db.prepare(`SELECT sm.signature_id, sm.similarity, sm.twin_similarity, s.provenance, s.kind, s.family
    FROM signature_match sm
    JOIN signature s ON s.id = sm.signature_id
    JOIN code_unit cu ON cu.id = sm.code_unit_id
    WHERE cu.repo_id = ?`).all(scanRow.repo_id);
  return {
    repo_name: repoName,
    report_file: reportFileName(repoName),
    report_path: reportFile,
    scan_id: scanRow.id,
    status: scanRow.status,
    check,
    cache_hit: extras.cacheHit,
    idempotent_replay: extras.idempotent,
    analyzers_called: extras.analyzersCalled,
    system2: "not_run",
    corpus_digest: scanRow.corpus_digest,
    commit_sha: scanRow.commit_sha,
    analyzers,
    findings: renderedFindings.map((row) => publicFinding(row, role)),
    matches,
  };
}

function applyWaivers(db, scanId) {
  const rows = db.prepare("SELECT * FROM finding WHERE scan_id = ?").all(scanId);
  for (const row of rows) {
    if (row.gate !== "block" || !waiverActive(db, row.fingerprint)) continue;
    const factors = JSON.parse(row.factors);
    factors.waived = true;
    db.prepare("UPDATE finding SET gate = 'comment', factors = ? WHERE id = ?").run(JSON.stringify(factors), row.id);
    db.prepare("INSERT INTO audit_event (id, actor_role, action, detail) VALUES (?, 'appsec', 'waiver_applied', ?)").run(
      randomUUID(),
      JSON.stringify(safeDetail({ finding_id: row.id, fingerprint: row.fingerprint })),
    );
  }
}

function finishCached(db, scanId, extras) {
  applyWaivers(db, scanId);
  const scanRow = db.prepare("SELECT * FROM scan WHERE id = ?").get(scanId);
  return writeReport(db, scanRow, extras.role, {
    cacheHit: true,
    idempotent: extras.idempotent,
    analyzersCalled: false,
  });
}

const PROVENANCE_RANK = { scan_observed: 0, appsec_promotion: 1, checked_in: 2 };
const RISK_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const STORED_RISKS = new Set(Object.keys(RISK_RANK));
const RATING_INPUT = new Map([
  ["informational", "info"],
  ["info", "info"],
  ["low", "low"],
  ["medium", "medium"],
  ["high", "high"],
  ["critical", "critical"],
]);

function preferLikeness(hits) {
  if (!hits.length) return null;
  return [...hits].sort((left, right) =>
    (PROVENANCE_RANK[left.signature.provenance] ?? 9) - (PROVENANCE_RANK[right.signature.provenance] ?? 9))[0];
}

function matchUnit(unit, signatures, policy, db) {
  db.prepare("DELETE FROM signature_match WHERE code_unit_id = ?").run(unit.id);
  const insert = db.prepare("INSERT INTO signature_match (code_unit_id, signature_id, similarity, twin_similarity) VALUES (?, ?, ?, ?)");
  const vulnerableHits = [];
  const secureHits = [];
  for (const signature of signatures) {
    const score = similarity(unit.sketch, signature.sketch);
    if (!(score > 0)) continue;
    if (signature.kind === "vulnerable") vulnerableHits.push({ signature, score });
    else if (signature.kind === "patched_twin" || signature.kind === "approved_control") secureHits.push({ signature, score });
  }
  const bestVulnScore = vulnerableHits.reduce((max, hit) => Math.max(max, hit.score), 0);
  const bestSecureScore = secureHits.reduce((max, hit) => Math.max(max, hit.score), 0);
  const vulnTies = vulnerableHits.filter((hit) => hit.score === bestVulnScore);
  const secureTies = secureHits.filter((hit) => hit.score === bestSecureScore);
  const twin = bestSecureScore > 0 ? round(bestSecureScore) : null;
  for (const hit of vulnTies) insert.run(unit.id, hit.signature.id, round(hit.score), twin);
  for (const hit of secureTies) insert.run(unit.id, hit.signature.id, round(hit.score), twin);
  const bestVuln = preferLikeness(vulnTies);
  const bestSecure = preferLikeness(secureTies);
  return {
    vulnerable: bestVuln ? round(bestVuln.score) : null,
    twin,
    approved: bestSecure ? round(bestSecure.score) : null,
    candidate: Boolean(bestVuln && bestVuln.score >= policy.likeness_threshold && bestSecureScore < policy.patched_twin_max),
    suppressed: Boolean(bestSecure && bestSecure.score >= policy.likeness_threshold),
    family: bestVuln ? bestVuln.signature.family : null,
    differing: bestVuln ? differingTokens(unit.tokens, bestVuln.signature.tokens) : [],
    provenance: bestVuln ? bestVuln.signature.provenance : null,
    repo: bestVuln ? bestVuln.signature.source_repo : null,
    functionName: bestVuln ? bestVuln.signature.qualified_name : null,
    classId: bestVuln ? bestVuln.signature.class_id : null,
    risk: bestVuln ? bestVuln.signature.risk_rating : null,
  };
}

function readSourceLine(snapshotDir, relative, line, endLine) {
  if (!relative || relative === "unknown") return "";
  const full = path.join(snapshotDir, relative);
  if (!fs.existsSync(full)) return "";
  try {
    const lines = fs.readFileSync(full, "utf8").split(/\r?\n/);
    const start = Math.max(1, line || 1);
    const end = Math.min(lines.length, Math.max(start, endLine || start));
    const span = lines.slice(start - 1, end).join("\n").trim();
    const capped = span.length > 200 ? `${span.slice(0, 200)}…` : span;
    return scrub(capped);
  } catch {
    return "";
  }
}

function overlapsStatement(literal, concat) {
  if (literal.path !== concat.path) return false;
  const start = concat.line || 1;
  const end = concat.endLine || start;
  const line = literal.line || 1;
  return line >= start && line <= end;
}

function prepareHits(hits) {
  const concats = hits.filter((hit) => hit.ruleId === "js.sqli.string-concat");
  const resetTokens = hits.filter((hit) => hit.ruleId === "js.auth.reset-token");
  const secretLines = new Set(
    hits.filter((hit) => hit.ruleId === "gitleaks").map((hit) => `${hit.path}|${hit.line}`),
  );
  let weakerRemoved = 0;
  const withoutWeaker = [];
  for (const hit of hits) {
    if (hit.ruleId === "js.sql.literal" && concats.some((concat) => overlapsStatement(hit, concat))) {
      weakerRemoved += 1;
      continue;
    }
    if (hit.ruleId === "js.sensitive.log" && secretLines.has(`${hit.path}|${hit.line}`)) {
      weakerRemoved += 1;
      continue;
    }
    if (hit.ruleId === "js.crypto.md5-token" && hit.pattern === "weak-hash" && resetTokens.some((token) => overlapsStatement(hit, token))) {
      continue;
    }
    withoutWeaker.push(hit);
  }
  const seen = new Set();
  const unique = [];
  let duplicatesRemoved = 0;
  for (const hit of withoutWeaker) {
    const key = `${hit.ruleId}|${hit.path}|${hit.line}|${hit.column || 0}|${hit.pattern || ""}`;
    if (seen.has(key)) {
      duplicatesRemoved += 1;
      continue;
    }
    seen.add(key);
    unique.push(hit);
  }
  return { hits: unique, weakerRemoved, duplicatesRemoved };
}

function unitForHit(units, hit) {
  const containing = units.filter((item) => item.path === hit.path && hit.line >= item.start && hit.line <= item.end);
  const functions = containing.filter((item) => item.name !== "$file");
  const pool = functions.length ? functions : containing;
  if (!pool.length) return units.find((item) => item.path === hit.path) || null;
  pool.sort((a, b) => (a.end - a.start) - (b.end - b.start) || b.start - a.start);
  return pool[0];
}

function patternList(hit) {
  return [...(hit.patterns || []), hit.pattern].filter(Boolean);
}

function beforePosition(line, column, otherLine, otherColumn) {
  return line < otherLine || (line === otherLine && column <= otherColumn);
}

function hitRange(hit) {
  const startLine = hit.line || 1;
  const startColumn = hit.column || 1;
  let endLine = hit.endLine || startLine;
  let endColumn = hit.endColumn || 0;
  if (endLine < startLine || (endLine === startLine && endColumn <= startColumn)) {
    endLine = startLine;
    endColumn = startColumn + 1;
  }
  return { startLine, startColumn, endLine, endColumn };
}

function sameCode(left, right) {
  if (left.path !== right.path) return false;
  const a = hitRange(left);
  const b = hitRange(right);
  const aEndsFirst = beforePosition(a.endLine, a.endColumn, b.startLine, b.startColumn);
  const bEndsFirst = beforePosition(b.endLine, b.endColumn, a.startLine, a.startColumn);
  return !aEndsFirst && !bEndsFirst;
}

function cover(hit, other) {
  const a = hitRange(hit);
  const b = hitRange(other);
  if (!beforePosition(a.startLine, a.startColumn, b.startLine, b.startColumn)) {
    hit.line = b.startLine;
    hit.column = b.startColumn;
  }
  if (beforePosition(a.endLine, a.endColumn, b.endLine, b.endColumn)) {
    hit.endLine = b.endLine;
    hit.endColumn = b.endColumn;
  }
}

function fileLines(snapshotDir, relative, cache) {
  if (cache.has(relative)) return cache.get(relative);
  const full = path.join(snapshotDir, relative || "");
  let lines = [];
  if (relative && relative !== "unknown" && fs.existsSync(full)) {
    try {
      lines = fs.readFileSync(full, "utf8").split(/\r?\n/);
    } catch {
      lines = [];
    }
  }
  cache.set(relative, lines);
  return lines;
}

function readHitSpan(lines, hit) {
  if (!lines.length) return "";
  const range = hitRange(hit);
  const start = Math.min(lines.length, range.startLine) - 1;
  const end = Math.min(lines.length, range.endLine);
  if (start < 0 || end <= start) return "";
  const selected = lines.slice(start, end);
  if (selected.length === 1) {
    const from = Math.max(0, range.startColumn - 1);
    const to = Math.max(from, range.endColumn - 1);
    return selected[0].slice(from, to);
  }
  selected[0] = selected[0].slice(Math.max(0, range.startColumn - 1));
  const last = selected.length - 1;
  if (range.endColumn > 0) selected[last] = selected[last].slice(0, Math.max(0, range.endColumn - 1));
  return selected.join("\n");
}

function statementShape(lines, hit) {
  const text = readHitSpan(lines, hit).trim();
  if (!text) return "";
  const tokens = normalizeTokens(text);
  return tokens.length ? tokens.join(" ") : "";
}

function siteOf(item) {
  const range = hitRange(item.hit);
  return {
    line: range.startLine,
    endLine: range.endLine,
    column: item.hit.column || range.startColumn,
    endColumn: range.endColumn,
    functionName: item.unit.name === "$file" ? "" : item.unit.name,
    unit: item.unit,
  };
}

function clusterText(sites) {
  const snippets = sites.map((site) => site.snippet).filter(Boolean);
  if (snippets.length <= 1) return snippets[0] || "";
  const contiguous = sites.every((site, index) => {
    if (!index) return true;
    const previous = sites[index - 1].end_line || sites[index - 1].line;
    return site.line <= previous + 1;
  });
  return snippets.join(contiguous ? "\n" : "\n\n");
}

function adoptEarliest(item) {
  item.sites.sort((left, right) => (left.line - right.line) || ((left.column || 0) - (right.column || 0)));
  const first = item.sites[0];
  if (!first) return;
  item.unit = first.unit;
  item.hit.line = first.line;
  item.hit.endLine = first.endLine;
  item.hit.column = first.column;
  item.hit.endColumn = first.endColumn;
}

function collapseByShape(items, snapshotDir) {
  const cache = new Map();
  const kept = [];
  for (const item of items) {
    item.sites = [siteOf(item)];
    if (!item.spec.collapse) {
      kept.push(item);
      continue;
    }
    const shape = statementShape(fileLines(snapshotDir, item.hit.path, cache), item.hit);
    item.hit.shape = shape;
    const prior = shape
      ? kept.find((candidate) =>
        candidate.spec.collapse
        && candidate.hit.path === item.hit.path
        && candidate.hit.ruleId === item.hit.ruleId
        && (candidate.hit.pattern || "") === (item.hit.pattern || "")
        && candidate.hit.shape === shape)
      : null;
    if (!prior) {
      kept.push(item);
      continue;
    }
    prior.sites.push(siteOf(item));
  }
  for (const item of kept) adoptEarliest(item);
  return kept;
}

function collapseDrafted(drafted, snapshotDir) {
  const kept = [];
  for (const item of drafted) {
    if (!item.spec.collapse) {
      kept.push(item);
      continue;
    }
    const prior = kept.find((candidate) =>
      candidate.hit.ruleId === item.hit.ruleId
      && candidate.unit.id === item.unit.id
      && sameCode(candidate.hit, item.hit));
    if (!prior) {
      item.hit.patterns = patternList(item.hit);
      kept.push(item);
      continue;
    }
    prior.hit.patterns = [...new Set([...patternList(prior.hit), ...patternList(item.hit)])];
    cover(prior.hit, item.hit);
  }
  for (const item of kept) {
    const patterns = [...new Set(patternList(item.hit))];
    const chosen = patterns.length ? patterns : [];
    item.hit.patterns = chosen.length ? chosen : (item.spec.defaultPattern ? [item.spec.defaultPattern] : []);
    item.hit.pattern = choosePattern(item.spec, item.hit.patterns);
  }
  return collapseByShape(kept, snapshotDir);
}

function presentation(spec, hit, sourceLine) {
  const described = describeFinding(spec, {
    pattern: hit.pattern,
    patterns: hit.patterns,
    ruleId: hit.ruleId,
    message: hit.message,
    sourceLine,
    family: hit.family,
  });
  let next = spec.next;
  if (hit.pattern && spec.patternNext && spec.patternNext[hit.pattern]) next = spec.patternNext[hit.pattern];
  if (hit.ruleId === "detect-child-process" && /require\(/.test(hit.message || "")) {
    next = "Confirm this module is not used to run request data";
  }
  if (hit.ruleId === "detect-non-literal-fs-filename" && /\b(req|request)\b/.test(sourceLine || "")) {
    next = "Confirm this path is not taken from a request";
  }
  return { ...described, next };
}

function explainCheck(check, findings, dataClass) {
  const blocking = findings.filter((finding) => finding.gate === "block").length;
  if (check === "failure") {
    return blocking === 1
      ? "Deployment failed because 1 finding blocks it."
      : `Deployment failed because ${blocking} findings block it.`;
  }
  const commentedHigh = findings.filter((finding) =>
    (finding.risk_rating === "high" || finding.risk_rating === "critical")
    && finding.gate === "comment"
    && finding.disposition !== "suppressed");
  if (commentedHigh.length && dataClass && dataClass !== "restricted") {
    const noun = commentedHigh.length === 1 ? "finding is a comment" : "findings are comments";
    return `Deployment passed because every finding is a comment. ${commentedHigh.length} high ${noun} because the data class is ${dataClass}.`;
  }
  return "Deployment passed because no finding blocks it.";
}

function riskRank(risk) {
  return RISK_RANK[risk] ?? 9;
}

function writeObserved(db, version, row) {
  const featureRef = `observed/${row.contentHash}`;
  const existing = db.prepare("SELECT id, kind, provenance, risk_rating FROM signature WHERE feature_ref = ? OR content_hash = ?")
    .get(featureRef, row.contentHash);
  if (existing && existing.provenance !== "scan_observed") return;
  if (row.kind === "approved_control" && existing) return;
  if (existing && existing.kind === "vulnerable" && row.kind === "vulnerable" && riskRank(row.risk) >= riskRank(existing.risk_rating)) return;
  const sketch = JSON.stringify(row.sketch);
  const normalized = JSON.stringify(row.tokens);
  if (existing) {
    db.prepare(`UPDATE signature SET
      kind = ?, class_id = ?, corpus_version = ?, sketch = ?, family = ?, provenance = 'scan_observed',
      qualified_name = ?, content_hash = ?, normalized = ?, risk_rating = ?, rule_id = ?, source_repo = ?, source_path = ?
      WHERE id = ?`).run(
      row.kind,
      row.classId,
      version,
      sketch,
      row.family,
      row.qualifiedName,
      row.contentHash,
      normalized,
      row.risk,
      row.ruleId,
      row.repo,
      row.path,
      existing.id,
    );
    return;
  }
  db.prepare(`INSERT INTO signature
    (feature_ref, id, kind, class_id, corpus_version, sketch, family, provenance, qualified_name, content_hash, normalized, risk_rating, rule_id, source_repo, source_path)
    VALUES (?, ?, ?, ?, ?, ?, ?, 'scan_observed', ?, ?, ?, ?, ?, ?, ?)`).run(
    featureRef,
    randomUUID(),
    row.kind,
    row.classId,
    version,
    sketch,
    row.family,
    row.qualifiedName,
    row.contentHash,
    normalized,
    row.risk,
    row.ruleId,
    row.repo,
    row.path,
  );
}

function enrollObserved(db, scanId, units, policy) {
  const version = db.prepare("SELECT version FROM corpus_meta WHERE id = 1").get().version;
  const repoName = db.prepare(`SELECT r.name AS name FROM scan sc JOIN repo r ON r.id = sc.repo_id WHERE sc.id = ?`).get(scanId)?.name || "";
  const findings = db.prepare("SELECT * FROM finding WHERE scan_id = ?").all(scanId);
  const byUnit = new Map(units.map((unit) => [unit.id, unit]));
  const risky = new Map();
  const openHashes = new Set();
  for (const finding of findings) {
    if (finding.disposition !== "open") continue;
    const unit = byUnit.get(finding.code_unit_id);
    if (unit) openHashes.add(unit.contentHash);
    const factors = JSON.parse(finding.factors);
    if (policy.noisy_rules.includes(factors.rule_id)) continue;
    if (factors.rule_id === "likeness.candidate") continue;
    if (finding.class_id === "secrets") continue;
    if (!unit || unit.name === "$file") continue;
    const previous = risky.get(unit.contentHash);
    if (previous && riskRank(finding.risk_rating) >= riskRank(previous.risk)) continue;
    risky.set(unit.contentHash, {
      unit,
      risk: finding.risk_rating,
      classId: finding.class_id,
      ruleId: factors.rule_id,
    });
  }
  for (const entry of risky.values()) {
    writeObserved(db, version, {
      contentHash: entry.unit.contentHash,
      kind: "vulnerable",
      classId: entry.classId,
      sketch: entry.unit.sketch,
      tokens: entry.unit.tokens,
      family: entry.unit.name,
      qualifiedName: entry.unit.name,
      risk: entry.risk,
      ruleId: entry.ruleId,
      repo: repoName,
      path: entry.unit.path,
    });
  }
  for (const unit of units) {
    if (unit.name === "$file") continue;
    if (unit.tokens.length < 12) continue;
    if (risky.has(unit.contentHash) || openHashes.has(unit.contentHash)) continue;
    writeObserved(db, version, {
      contentHash: unit.contentHash,
      kind: "approved_control",
      classId: "none",
      sketch: unit.sketch,
      tokens: unit.tokens,
      family: unit.name,
      qualifiedName: unit.name,
      risk: null,
      ruleId: null,
      repo: repoName,
      path: unit.path,
    });
  }
}

export async function runScan({ eventPath, event: suppliedEvent, role }) {
  if (!ROLES.has(role)) throw new Error(`Unknown role ${role}`);
  const event = suppliedEvent || JSON.parse(fs.readFileSync(path.resolve(simRoot, eventPath), "utf8"));
  const policy = loadPolicy();
  const db = openDb();
  const corpus = syncCorpus(db);
  const rulepackDigest = sha256([policyPath, eslintConfigPath, localRulesPath, analyzersPath, advisoriesPath, fileURLToPath(import.meta.url)].map((file) => fs.readFileSync(file, "utf8")).join("\n"));
  const delivery = db.prepare("SELECT scan_id FROM delivery WHERE delivery_id = ?").get(event.delivery_id);
  if (delivery) return finishCached(db, delivery.scan_id, { role, idempotent: true });

  db.prepare(`INSERT INTO service (id, name, data_class, gate_profile, owner_team_id)
    VALUES (?, ?, ?, 'standard', ?)
    ON CONFLICT(id) DO UPDATE SET data_class = excluded.data_class, name = excluded.name, owner_team_id = excluded.owner_team_id`)
    .run(event.service_id, event.service_name, event.data_class, event.owner_team_id);
  db.prepare(`INSERT INTO repo (id, name, service_id) VALUES (?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET name = excluded.name, service_id = excluded.service_id`)
    .run(event.repo_id, event.repo_name, event.service_id);

  const cached = db.prepare("SELECT id FROM scan WHERE repo_id = ? AND commit_sha = ? AND rulepack_digest = ? AND corpus_digest = ?")
    .get(event.repo_id, event.commit_sha, rulepackDigest, corpus.digest);
  if (cached) {
    db.prepare("INSERT INTO delivery (delivery_id, scan_id) VALUES (?, ?)").run(event.delivery_id, cached.id);
    return finishCached(db, cached.id, { role, idempotent: false });
  }

  const sourceDir = path.resolve(simRoot, event.source_dir);
  if (!fs.existsSync(sourceDir) || !fs.statSync(sourceDir).isDirectory()) {
    throw new Error(`Source directory not found: ${sourceDir}`);
  }
  const external = Boolean(event.external);
  const maxFiles = external ? policy.external_max_files : policy.max_files;
  const maxBytes = external ? policy.external_max_total_bytes : policy.max_total_bytes;
  const accepted = [];
  const skipped = [];
  let bytes = 0;
  for (const file of walk(sourceDir)) {
    const size = fs.statSync(file).size;
    if (size > policy.max_file_bytes) {
      if (!external) throw new Error("Fixture file exceeds the snapshot cap");
      skipped.push(path.relative(sourceDir, file));
      continue;
    }
    accepted.push(file);
    bytes += size;
  }
  if (accepted.length === 0) throw new Error(`No files to scan under ${sourceDir}`);
  if (accepted.length > maxFiles || bytes > maxBytes) {
    throw new Error(`Source exceeds the snapshot cap (${accepted.length} files, ${bytes} bytes). Limit is ${maxFiles} files and ${maxBytes} bytes. Scan a subdirectory, or raise external_max_files and external_max_total_bytes in policy.json.`);
  }

  const [job] = drain([{ sourceDir, sha: event.commit_sha, files: accepted }], (item) => item);
  const snapshotDir = copySnapshot(job.sourceDir, job.sha, job.files);
  bumpAnalyzers();
  const eslintRun = await runEslint(snapshotDir, policy.lint_ignore || []);
  const analyzerRuns = [
    { name: "eslint", ...eslintRun },
    { name: "templates", ...runTemplates(snapshotDir, policy.lint_ignore || []) },
    { name: "advisories", ...runAdvisories(snapshotDir) },
    { name: "npm-audit", ...runNpmAudit(snapshotDir) },
    { name: "gitleaks", ...runGitleaks(snapshotDir) },
    { name: "trivy", ...runTrivy(snapshotDir) },
  ];
  const analyzers = analyzerRuns.map((run) => {
    if (run.name === "eslint" && run.skippedVendor) {
      const noun = run.skippedVendor === 1 ? "file" : "files";
      return { name: run.name, status: `${run.status}, skipped ${run.skippedVendor} vendor or generated ${noun}` };
    }
    return { name: run.name, status: run.status };
  });
  if (skipped.length) analyzers.push({ name: "snapshot", status: `skipped ${skipped.length} oversize files` });
  const prepared = prepareHits(analyzerRuns.flatMap((run) => run.findings || []));
  analyzers.push({
    name: "triage",
    status: "recorded",
    vendor_files_skipped: eslintRun.skippedVendor || 0,
    duplicates_removed: prepared.duplicatesRemoved,
    weaker_removed: prepared.weakerRemoved,
  });
  const hits = prepared.hits;

  const scanId = randomUUID();
  db.prepare(`INSERT INTO scan (id, repo_id, commit_sha, rulepack_digest, corpus_digest, status, snapshot_dir, analyzers_json)
    VALUES (?, ?, ?, ?, ?, 'complete', ?, ?)`).run(
    scanId, event.repo_id, event.commit_sha, rulepackDigest, corpus.digest, snapshotDir, JSON.stringify(analyzers),
  );
  db.prepare("INSERT INTO delivery (delivery_id, scan_id) VALUES (?, ?)").run(event.delivery_id, scanId);

  const units = [];
  const sourceFiles = accepted.filter((file) => /\.(js|jsx|json|tf|ejs)$/i.test(file));
  for (const file of sourceFiles) {
    const relative = path.relative(sourceDir, file).replaceAll("\\", "/");
    const source = fs.readFileSync(file, "utf8");
    const functions = extractFunctions(source);
    const pieces = [
      ...functions,
      { name: "$file", body: source, line: 1, endLine: Math.max(1, source.split("\n").length) },
    ];
    for (const piece of pieces) {
      const tokens = normalizeTokens(piece.body);
      const contentHash = sha256(tokens.join("\n"));
      const existing = db.prepare("SELECT id FROM code_unit WHERE repo_id = ? AND path = ? AND qualified_name = ? AND content_hash = ?")
        .get(event.repo_id, relative, piece.name, contentHash);
      const id = existing?.id || randomUUID();
      const sketch = sketchOf(tokens);
      if (!existing) {
        db.prepare(`INSERT INTO code_unit
          (id, repo_id, path, qualified_name, content_hash, normalized, sketch, start_line, end_line)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
          id, event.repo_id, relative, piece.name, contentHash, tokens.join(" "), JSON.stringify(sketch), piece.line, piece.endLine,
        );
      }
      units.push({
        id,
        path: relative,
        name: piece.name,
        tokens,
        sketch,
        contentHash,
        start: piece.line,
        end: piece.endLine,
        untrusted: sawUntrustedInstruction(source),
        likeness: null,
      });
    }
  }
  for (const unit of units) unit.likeness = matchUnit(unit, corpus.signatures, policy, db);

  const drafted = [];
  for (const hit of hits) {
    const unit = unitForHit(units, hit);
    if (!unit) continue;
    const spec = RULES[hit.ruleId];
    if (!spec) continue;
    drafted.push({ hit, unit, spec });
  }
  for (const unit of units) {
    const fileHasFunction = units.some((other) => other.path === unit.path && other.name !== "$file");
    if (unit.name === "$file" && fileHasFunction) continue;
    const covered = drafted.some((item) => item.unit.id === unit.id);
    if (unit.likeness.candidate && !covered) {
      drafted.push({
        hit: {
          ruleId: "likeness.candidate",
          path: unit.path,
          line: unit.start,
          column: 0,
          message: "Similar to a vulnerable corpus sample.",
          family: unit.likeness.family,
        },
        unit,
        spec: RULES["likeness.candidate"],
      });
    }
  }

  const collapsed = collapseDrafted(drafted, snapshotDir);
  const system2 = review();
  const usedFingerprints = new Set();
  const overrideRating = db.prepare("SELECT risk_rating FROM risk_override WHERE fingerprint = ?");
  for (const item of collapsed) {
    const fingerprint = sha256([
      event.repo_id,
      item.hit.ruleId,
      item.unit.path,
      item.unit.name,
      item.spec.classId,
      String(item.hit.line),
      String(item.hit.column || 0),
    ].join("|")).slice(0, 16);
    if (usedFingerprints.has(fingerprint)) continue;
    usedFingerprints.add(fingerprint);
    const sites = (item.sites && item.sites.length ? item.sites : [siteOf(item)]).map((site) => ({
      line: site.line,
      end_line: site.endLine,
      column: site.column || null,
      function_name: site.functionName || "",
      snippet: readSourceLine(snapshotDir, item.hit.path, site.line, site.endLine),
    }));
    const sourceLine = item.hit.sourceLine || clusterText(sites);
    const copy = presentation(item.spec, item.hit, sourceLine);
    const suppressed = policy.noisy_rules.includes(item.hit.ruleId) && item.unit.likeness.suppressed;
    const waived = waiverActive(db, fingerprint);
    const precision = precisionFor(item.spec, item.hit.pattern);
    const ruleRisk = item.spec.risk;
    const savedRating = overrideRating.get(fingerprint)?.risk_rating;
    const risk = STORED_RISKS.has(savedRating) ? savedRating : ruleRisk;
    const gate = decideGate({
      suppressed,
      waived,
      system2Only: false,
      classId: item.spec.classId,
      precision,
      risk: ruleRisk,
      dataClass: event.data_class,
    }, policy);
    const factors = {
      rule_id: item.hit.ruleId,
      taxonomy_id: item.spec.taxonomyId,
      pattern: item.hit.pattern || "",
      patterns: item.hit.patterns || [],
      evidence_type: item.spec.evidenceType,
      rule_precision_band: precision,
      likeness_vulnerable: item.unit.likeness.vulnerable,
      likeness_patched_twin: item.unit.likeness.twin,
      likeness_candidate: item.unit.likeness.candidate,
      likeness_family: item.unit.likeness.family,
      likeness_provenance: item.unit.likeness.provenance,
      likeness_repo: item.unit.likeness.repo,
      likeness_function: item.unit.likeness.functionName,
      likeness_class: item.unit.likeness.classId,
      likeness_risk: item.unit.likeness.risk,
      reachable_from_diff: true,
      system2: system2.system2,
      untrusted_comment_ignored: item.unit.untrusted,
      waived,
      suppressed_by: suppressed ? "approved_control" : null,
    };
    const evidence = {
      path: item.hit.path,
      line: item.hit.line,
      column: item.hit.column || null,
      function_name: item.unit.name === "$file" ? "" : item.unit.name,
      source_line: sourceLine,
      sites,
      title: copy.finding,
      class_label: copy.classLabel,
      subclass: copy.subclass,
      finding_name: copy.finding,
      problem: copy.problem,
      next_step: copy.next,
      message: item.hit.message,
      differing_tokens: item.unit.likeness.differing,
    };
    if (item.hit.secretHash) {
      evidence.secretHash = item.hit.secretHash;
      evidence.secretPreview = item.hit.secretPreview;
    }
    db.prepare(`INSERT INTO finding
      (id, scan_id, code_unit_id, class_id, cwe, risk_rating, model_confidence, calibrated_probability, disposition, fingerprint, gate, factors, system2, evidence)
      VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?)`).run(
      randomUUID(),
      scanId,
      item.unit.id,
      item.spec.classId,
      JSON.stringify(item.spec.cwe || CWE[item.spec.classId] || []),
      risk,
      item.hit.ruleId === "likeness.candidate" ? item.unit.likeness.vulnerable : (precision === "high" ? 0.9 : 0.45),
      suppressed ? "suppressed" : "open",
      fingerprint,
      gate,
      JSON.stringify(factors),
      system2.system2,
      JSON.stringify(evidence),
    );
  }

  enrollObserved(db, scanId, units, policy);

  db.prepare("INSERT INTO audit_event (id, actor_role, action, detail) VALUES (?, ?, 'scan_completed', ?)").run(
    randomUUID(),
    role,
    JSON.stringify(safeDetail({ scan_id: scanId, check: checkFromFindings(db.prepare("SELECT gate FROM finding WHERE scan_id = ?").all(scanId)) })),
  );
  const scanRow = db.prepare("SELECT * FROM scan WHERE id = ?").get(scanId);
  return writeReport(db, scanRow, role, { cacheHit: false, idempotent: false, analyzersCalled: true });
}

export function setRiskRating({ findingId, riskRating, role }) {
  const stored = RATING_INPUT.get(String(riskRating || "").trim().toLowerCase());
  if (!stored) throw new Error("Unknown risk rating");
  if (!/^[0-9a-f-]{36}$/i.test(String(findingId || ""))) throw new Error("Finding not found");
  if (!ROLES.has(role)) throw new Error("Unknown role");
  const db = openDb();
  try {
    const finding = db.prepare(`SELECT f.id, f.fingerprint, sc.repo_id
      FROM finding f
      JOIN scan sc ON sc.id = f.scan_id
      WHERE f.id = ?`).get(findingId);
    if (!finding) throw new Error("Finding not found");
    db.exec("BEGIN");
    db.prepare(`INSERT INTO risk_override (fingerprint, risk_rating, updated_at)
      VALUES (?, ?, datetime('now'))
      ON CONFLICT(fingerprint) DO UPDATE SET
        risk_rating = excluded.risk_rating,
        updated_at = excluded.updated_at`).run(finding.fingerprint, stored);
    db.prepare("UPDATE finding SET risk_rating = ? WHERE fingerprint = ?").run(stored, finding.fingerprint);
    db.prepare("INSERT INTO audit_event (id, actor_role, action, detail) VALUES (?, ?, 'risk_rating_changed', ?)").run(
      randomUUID(),
      role,
      JSON.stringify(safeDetail({ finding_id: findingId, fingerprint: finding.fingerprint, risk_rating: stored })),
    );
    const latest = db.prepare("SELECT * FROM scan WHERE repo_id = ? ORDER BY created_at DESC, id DESC LIMIT 1").get(finding.repo_id);
    const cacheHit = latest.report_cache_hit === 1 ? true : latest.report_cache_hit === 0 ? false : null;
    const written = writeReport(db, latest, role, {
      cacheHit,
      idempotent: false,
      analyzersCalled: false,
    }, { archivePrevious: false, auditView: false });
    db.exec("COMMIT");
    return {
      risk_rating: stored,
      report_file: written.report_file,
      report_path: written.report_path,
      repo_name: written.repo_name,
    };
  } catch (error) {
    try {
      db.exec("ROLLBACK");
    } catch {
      // The failure happened before a transaction was open.
    }
    throw error;
  } finally {
    db.close();
  }
}

export function adjudicate({ findingId, label, role }) {
  if (role === "auditor") throw new Error("Auditor cannot adjudicate");
  if (role !== "developer" && role !== "appsec") throw new Error(`Unknown role ${role}`);
  const allowed = new Set(["false_positive", "true_positive", "accepted_risk"]);
  if (!allowed.has(label)) throw new Error("Unknown adjudication label");
  const db = openDb();
  const before = db.prepare("SELECT COUNT(*) AS n FROM signature WHERE provenance = 'appsec_promotion'").get().n;
  const finding = db.prepare("SELECT id FROM finding WHERE id = ?").get(findingId);
  if (!finding) throw new Error("Finding not found");
  db.prepare("INSERT INTO adjudication (id, finding_id, label, actor_role) VALUES (?, ?, ?, ?)").run(randomUUID(), findingId, label, role);
  db.prepare("UPDATE finding SET disposition = ? WHERE id = ?").run(label, findingId);
  if (label === "false_positive") {
    const unit = db.prepare("SELECT content_hash FROM code_unit WHERE id = (SELECT code_unit_id FROM finding WHERE id = ?)").get(findingId);
    if (unit?.content_hash) {
      db.prepare("DELETE FROM signature WHERE provenance = 'scan_observed' AND kind = 'vulnerable' AND content_hash = ?").run(unit.content_hash);
    }
  }
  const after = db.prepare("SELECT COUNT(*) AS n FROM signature WHERE provenance = 'appsec_promotion'").get().n;
  const still = db.prepare("SELECT id, disposition FROM finding WHERE id = ?").get(findingId);
  db.prepare("INSERT INTO audit_event (id, actor_role, action, detail) VALUES (?, ?, 'adjudicate', ?)").run(
    randomUUID(),
    role,
    JSON.stringify(safeDetail({ finding_id: findingId, label })),
  );
  return {
    finding_id: findingId,
    disposition: still.disposition,
    finding_still_present: Boolean(still),
    signature_created: after > before,
  };
}

export function promoteSignature({ codeUnitId, role }) {
  if (role !== "appsec") throw new Error("Only appsec can promote a signature");
  const db = openDb();
  const unit = db.prepare("SELECT * FROM code_unit WHERE id = ?").get(codeUnitId);
  if (!unit) throw new Error("Code unit not found");
  const scan = db.prepare(`SELECT snapshot_dir FROM scan WHERE repo_id = ? AND snapshot_dir IS NOT NULL ORDER BY created_at DESC LIMIT 1`).get(unit.repo_id);
  if (!scan) throw new Error("Snapshot not found");
  const source = fs.readFileSync(path.join(scan.snapshot_dir, unit.path), "utf8");
  const fn = extractFunctions(source).find((item) => item.name === unit.qualified_name);
  const body = fn ? fn.body : source;
  const id = randomUUID();
  const promotedDir = path.join(corpusDir, "promoted");
  fs.mkdirSync(promotedDir, { recursive: true });
  fs.writeFileSync(path.join(promotedDir, `${id}.js`), body);
  fs.writeFileSync(path.join(promotedDir, `${id}.json`), JSON.stringify({
    kind: "vulnerable",
    class_id: "injection",
    family: unit.qualified_name,
    qualified_name: unit.qualified_name,
    provenance: "appsec_promotion",
    source_file: `${id}.js`,
  }, null, 2));
  db.prepare("UPDATE corpus_meta SET version = version + 1 WHERE id = 1").run();
  const corpus = syncCorpus(db);
  const signature = db.prepare("SELECT id FROM signature WHERE feature_ref = ?").get(`promoted/${id}.json`);
  db.prepare("INSERT INTO audit_event (id, actor_role, action, detail) VALUES (?, 'appsec', 'promote_signature', ?)").run(
    randomUUID(),
    JSON.stringify(safeDetail({ code_unit_id: codeUnitId, signature_id: signature.id })),
  );
  return { signature_id: signature.id, corpus_digest: corpus.digest, corpus_version: corpus.version };
}

export function waive({ fingerprint, reason, hours, role }) {
  if (role !== "appsec") throw new Error("Only appsec can approve a waiver");
  const db = openDb();
  const id = randomUUID();
  const expiresAt = new Date(Date.now() + Number(hours) * 60 * 60 * 1000).toISOString();
  db.prepare("INSERT INTO waiver (id, fingerprint, approver, reason, expires_at) VALUES (?, ?, ?, ?, ?)").run(
    id, fingerprint, role, reason, expiresAt,
  );
  const still = db.prepare("SELECT COUNT(*) AS n FROM finding WHERE fingerprint = ?").get(fingerprint).n;
  db.prepare("INSERT INTO audit_event (id, actor_role, action, detail) VALUES (?, 'appsec', 'waiver_created', ?)").run(
    randomUUID(),
    JSON.stringify(safeDetail({ fingerprint, expires_at: expiresAt })),
  );
  return { waiver_id: id, fingerprint, expires_at: expiresAt, findings_retained: still };
}
