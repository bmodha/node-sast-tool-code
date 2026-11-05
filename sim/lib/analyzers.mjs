import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { ESLint } from "eslint";
import { advisoriesPath, eslintConfigPath } from "./paths.mjs";
import { previewSecret, scrub } from "./redact.mjs";
import { stableRuleId } from "./policy.mjs";
import { createHash } from "node:crypto";

function relativeToSnapshot(snapshotDir, file) {
  if (!file) return "unknown";
  const absolute = path.isAbsolute(file) ? file : path.resolve(snapshotDir, file);
  return path.relative(snapshotDir, absolute).replaceAll("\\", "/");
}

function commandExists(name) {
  const finder = process.platform === "win32" ? "where.exe" : "which";
  const result = spawnSync(finder, [name], { encoding: "utf8", windowsHide: true });
  return result.status === 0;
}

function npmCommand() {
  return process.platform === "win32" ? "npm.cmd" : "npm";
}

function javascriptFiles(dir) {
  const files = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === "node_modules") continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) files.push(...javascriptFiles(full));
    else if (entry.name.endsWith(".js") || entry.name.endsWith(".jsx")) files.push(full);
  }
  return files;
}

function splitPattern(message) {
  const text = String(message);
  const match = text.match(/ \[pattern:([a-z0-9-]+)\]$/);
  if (!match) return { message: text, pattern: "" };
  return { message: text.slice(0, match.index), pattern: match[1] };
}

export function isLintIgnored(relative, patterns = []) {
  const normalized = String(relative || "").replaceAll("\\", "/");
  const base = normalized.split("/").pop();
  return patterns.some((pattern) => {
    if (pattern.startsWith("*.")) return base.endsWith(pattern.slice(1));
    const dir = pattern.endsWith("/") ? pattern : `${pattern}/`;
    return normalized === dir.slice(0, -1) || normalized.startsWith(dir) || normalized.includes(`/${dir}`);
  });
}

export async function runEslint(snapshotDir, ignorePatterns = []) {
  const skippedVendor = [];
  const files = [];
  for (const file of javascriptFiles(snapshotDir)) {
    const relative = path.relative(snapshotDir, file).replaceAll("\\", "/");
    if (isLintIgnored(relative, ignorePatterns)) skippedVendor.push(relative);
    else files.push(file);
  }
  if (files.length === 0) return { status: "ok", findings: [], skippedVendor: skippedVendor.length };
  const eslint = new ESLint({
    cwd: path.dirname(eslintConfigPath),
    overrideConfigFile: eslintConfigPath,
    allowInlineConfig: false,
    errorOnUnmatchedPattern: false,
  });
  const results = await eslint.lintFiles(files);
  const findings = [];
  for (const result of results) {
    const relative = path.relative(snapshotDir, result.filePath).replaceAll("\\", "/");
    for (const message of result.messages) {
      const ruleId = stableRuleId(message.ruleId);
      if (!ruleId) continue;
      const parsed = splitPattern(scrub(message.message || ruleId));
      findings.push({
        ruleId,
        path: relative,
        line: message.line || 1,
        endLine: message.endLine || message.line || 1,
        column: message.column || 0,
        endColumn: message.endColumn || 0,
        message: parsed.message,
        pattern: parsed.pattern,
      });
    }
  }
  return { status: "ok", findings, skippedVendor: skippedVendor.length };
}

export function runNpmAudit(snapshotDir) {
  const findings = [];
  const hasManifest = fs.existsSync(path.join(snapshotDir, "package.json"));
  const hasLock = fs.existsSync(path.join(snapshotDir, "package-lock.json"));
  if (hasManifest && !hasLock) {
    findings.push({
      ruleId: "npm-audit",
      path: "package.json",
      line: 1,
      column: 0,
      pattern: "missing-lockfile",
      message: "Dependency manifest has no lockfile",
    });
  }
  const result = spawnSync(npmCommand(), ["audit", "--json", "--package-lock-only"], {
    cwd: snapshotDir,
    encoding: "utf8",
    windowsHide: true,
    timeout: 20000,
    shell: process.platform === "win32",
    env: { ...process.env, npm_config_ignore_scripts: "true" },
  });
  if (result.error || (result.status !== 0 && !result.stdout)) {
    return {
      status: findings.length ? "ok" : "skipped",
      findings,
      detail: findings.length ? "" : "npm audit unavailable",
    };
  }
  let parsed;
  try {
    parsed = JSON.parse(result.stdout || "{}");
  } catch {
    return {
      status: findings.length ? "ok" : "skipped",
      findings,
      detail: findings.length ? "" : "npm audit returned non-json",
    };
  }
  const vulnerabilities = parsed.vulnerabilities || {};
  for (const [name, entry] of Object.entries(vulnerabilities)) {
    findings.push({
      ruleId: "npm-audit",
      path: "package.json",
      line: 1,
      message: scrub(`${name} ${entry.severity || "unknown"}`),
    });
  }
  return { status: "ok", findings };
}

export function runGitleaks(snapshotDir) {
  if (!commandExists("gitleaks")) return { status: "skipped", findings: [] };
  const reportPath = path.join(os.tmpdir(), `gitleaks-${createHash("sha256").update(snapshotDir).digest("hex").slice(0, 12)}.json`);
  const result = spawnSync("gitleaks", [
    "detect", "--source", snapshotDir, "--no-git", "--report-format", "json", "--report-path", reportPath,
  ], { encoding: "utf8", windowsHide: true, timeout: 20000 });
  try {
    if (!fs.existsSync(reportPath)) return { status: "skipped", findings: [], detail: scrub(result.stderr || "no report") };
    const raw = fs.readFileSync(reportPath, "utf8");
    const items = JSON.parse(raw || "[]");
    const findings = items.map((item) => {
      const secret = item.Secret || item.Match || "";
      return {
        ruleId: "gitleaks",
        path: relativeToSnapshot(snapshotDir, item.File),
        line: item.StartLine || 1,
        message: "credential pattern",
        secretHash: createHash("sha256").update(String(secret)).digest("hex"),
        secretPreview: previewSecret(secret),
      };
    });
    return { status: "ok", findings };
  } catch {
    return { status: "skipped", findings: [] };
  } finally {
    fs.rmSync(reportPath, { force: true });
  }
}

export function runTrivy(snapshotDir) {
  if (!commandExists("trivy")) return { status: "skipped", findings: [] };
  const result = spawnSync("trivy", [
    "config", "--format", "json", "--quiet", "--skip-dirs", "node_modules", snapshotDir,
  ], { encoding: "utf8", windowsHide: true, timeout: 30000 });
  if (result.error || !result.stdout) return { status: "skipped", findings: [] };
  let parsed;
  try {
    parsed = JSON.parse(result.stdout);
  } catch {
    return { status: "skipped", findings: [] };
  }
  const findings = [];
  for (const entry of parsed.Results || []) {
    const relative = relativeToSnapshot(snapshotDir, entry.Target || "unknown");
    for (const misconfig of entry.Misconfigurations || []) {
      const critical = String(misconfig.Severity || "").toUpperCase() === "CRITICAL";
      findings.push({
        ruleId: critical ? "trivy-critical" : "trivy-other",
        path: relative,
        line: misconfig.CauseMetadata?.StartLine || 1,
        message: scrub(misconfig.Title || misconfig.ID || "iac misconfiguration"),
      });
    }
  }
  return { status: "ok", findings };
}

function filesUnder(dir, accept) {
  const files = [];
  if (!fs.existsSync(dir)) return files;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === "node_modules" || entry.name === ".git") continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) files.push(...filesUnder(full, accept));
    else if (accept(entry.name)) files.push(full);
  }
  return files;
}

function lineColumn(source, index) {
  const before = source.slice(0, Math.max(0, index));
  const line = before.split(/\n/).length;
  const lastBreak = before.lastIndexOf("\n");
  return { line, column: index - lastBreak };
}

export function runTemplates(snapshotDir, ignorePatterns = []) {
  const findings = [];
  const unescaped = /<%-([\s\S]*?)%>/g;
  const innerHtml = /\.innerHTML\s*=\s*([^;\n]+)/g;
  for (const file of filesUnder(snapshotDir, (name) => name.endsWith(".ejs"))) {
    const relative = path.relative(snapshotDir, file).replaceAll("\\", "/");
    if (isLintIgnored(relative, ignorePatterns)) continue;
    const source = fs.readFileSync(file, "utf8");
    for (const match of source.matchAll(unescaped)) {
      const body = match[1].trim();
      if (body.startsWith("include")) continue;
      const at = lineColumn(source, match.index);
      findings.push({
        ruleId: "js.xss.template",
        path: relative,
        line: at.line,
        endLine: at.line,
        column: at.column,
        endColumn: at.column + match[0].length,
        pattern: "template",
        message: "Unescaped template output",
      });
    }
    for (const match of source.matchAll(innerHtml)) {
      const value = match[1].trim();
      if (/^(['"`])[\s\S]*\1$/.test(value)) continue;
      const at = lineColumn(source, match.index);
      findings.push({
        ruleId: "js.xss.dangerous-html",
        path: relative,
        line: at.line,
        endLine: at.line,
        column: at.column,
        endColumn: at.column + match[0].length,
        pattern: "html",
        message: "Unsanitized HTML sink",
      });
    }
  }
  return { status: "ok", findings };
}

export function runAdvisories(snapshotDir) {
  let listed = [];
  try {
    const parsed = JSON.parse(fs.readFileSync(advisoriesPath, "utf8"));
    listed = Array.isArray(parsed.packages) ? parsed.packages : [];
  } catch {
    return { status: "skipped", findings: [], detail: "advisory list unavailable" };
  }
  const findings = [];
  for (const file of filesUnder(snapshotDir, (name) => name === "package.json")) {
    let manifest;
    try {
      manifest = JSON.parse(fs.readFileSync(file, "utf8"));
    } catch {
      continue;
    }
    const relative = path.relative(snapshotDir, file).replaceAll("\\", "/");
    const source = fs.readFileSync(file, "utf8");
    const declared = { ...manifest.dependencies, ...manifest.devDependencies };
    for (const entry of listed) {
      const spec = declared[entry.name];
      if (String(spec || "").trim() !== String(entry.version || "").trim()) continue;
      const needle = `"${entry.name}"`;
      const index = source.indexOf(needle);
      const at = lineColumn(source, index < 0 ? 0 : index);
      findings.push({
        ruleId: "js.supply.advisory",
        path: relative,
        line: at.line,
        endLine: at.line,
        column: at.column,
        pattern: "advisory",
        message: `${entry.name} ${entry.version} is a known vulnerable release`,
      });
    }
  }
  return { status: "ok", findings };
}
