import fs from "node:fs";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { outDir } from "./paths.mjs";

export const reportServerHost = "127.0.0.1";
export const reportServerPort = 47321;

export function reportServerOrigin() {
  return `http://${reportServerHost}:${reportServerPort}`;
}

export function safeRepoName(repoName) {
  const safe = String(repoName || "repo")
    .replace(/[^A-Za-z0-9._-]/g, "-")
    .replace(/^\.+/, "")
    .replace(/^-+|-+$/g, "") || "repo";
  return safe.slice(0, 80);
}

export function reportFileName(repoName) {
  return `${safeRepoName(repoName)}_report.html`;
}

export function reportPathFor(repoName) {
  return path.join(outDir, reportFileName(repoName));
}

export function dashboardFileName() {
  return "dashboard.html";
}

export function dashboardPath() {
  return path.join(outDir, dashboardFileName());
}

export function archiveDirFor(repoName) {
  return path.join(outDir, "archive", safeRepoName(repoName));
}

const STAMP = /^(\d{4}-\d{2}-\d{2})_(\d{2})-(\d{2})-(\d{2})(?:_(\d+))?$/;

export function stampFromDate(date) {
  const iso = date.toISOString();
  return `${iso.slice(0, 10)}_${iso.slice(11, 13)}-${iso.slice(14, 16)}-${iso.slice(17, 19)}`;
}

export function archiveLabel(stamp) {
  const match = STAMP.exec(stamp);
  if (!match) return stamp;
  const suffix = match[5] ? ` (${match[5]})` : "";
  return `${match[1]} ${match[2]}:${match[3]}:${match[4]} UTC${suffix}`;
}

export function listReportArchive(repoName) {
  const dir = archiveDirFor(repoName);
  if (!fs.existsSync(dir)) return [];
  const safe = safeRepoName(repoName);
  const prefix = `${safe}_report_`;
  return fs.readdirSync(dir)
    .filter((name) => name.startsWith(prefix) && name.endsWith(".html"))
    .map((name) => {
      const stamp = name.slice(prefix.length, -".html".length);
      return {
        href: `archive/${safe}/${name}`,
        label: `${reportFileName(repoName)} · ${archiveLabel(stamp)}`,
        stamp,
      };
    })
    .filter((item) => STAMP.test(item.stamp))
    .sort((left, right) => right.stamp.localeCompare(left.stamp));
}

export function archivePreviousReport(repoName) {
  const current = reportPathFor(repoName);
  if (!fs.existsSync(current)) return null;
  const safe = safeRepoName(repoName);
  const dir = archiveDirFor(repoName);
  fs.mkdirSync(dir, { recursive: true });
  const base = stampFromDate(fs.statSync(current).mtime);
  let stamp = base;
  let dest = path.join(dir, `${safe}_report_${stamp}.html`);
  let n = 2;
  while (fs.existsSync(dest)) {
    stamp = `${base}_${n}`;
    dest = path.join(dir, `${safe}_report_${stamp}.html`);
    n += 1;
  }
  let html = fs.readFileSync(current, "utf8");
  const folder = `archive/${safe}/`;
  html = html.replaceAll(`href="${folder}`, 'href="');
  html = html.replace(
    "<body ",
    `<body data-current-href="../../${reportFileName(repoName)}" data-archived="1" `,
  );
  const label = archiveLabel(stamp);
  html = html.replace(
    '<div class="page">',
    `<div class="page">\n    <p class="saved">Archived report from ${label}. <a href="../../${reportFileName(repoName)}">Back to the current report</a></p>`,
  );
  fs.writeFileSync(dest, html);
  return dest;
}

const tokenPath = path.join(outDir, "report-token");

export function reportToken() {
  fs.mkdirSync(outDir, { recursive: true });
  if (!fs.existsSync(tokenPath)) fs.writeFileSync(tokenPath, randomBytes(24).toString("hex"));
  return fs.readFileSync(tokenPath, "utf8").trim();
}

export function readReportToken() {
  if (!fs.existsSync(tokenPath)) return "";
  return fs.readFileSync(tokenPath, "utf8").trim();
}
