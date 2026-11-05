import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { spawn } from "node:child_process";
import { timingSafeEqual } from "node:crypto";
import { outDir, simRoot } from "./paths.mjs";
import {
  dashboardFileName,
  readReportToken,
  reportServerHost,
  reportServerOrigin,
  reportServerPort,
  reportToken,
  safeRepoName,
} from "./report-files.mjs";

const CURRENT_FILE = /^[A-Za-z0-9._-]+_report\.html$/;
const ARCHIVED_FILE = /^[A-Za-z0-9._-]+_report_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}(?:_\d+)?\.html$/;

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Private-Network": "true",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Accept",
    "Cache-Control": "no-store",
  };
}

function send(res, status, body, type) {
  res.writeHead(status, { "Content-Type": type, ...corsHeaders() });
  res.end(body);
}

function tokenMatches(got) {
  const expected = readReportToken();
  const left = Buffer.from(expected);
  const right = Buffer.from(String(got || ""));
  if (!left.length || left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

function insideOut(file) {
  const root = path.resolve(outDir);
  const resolved = path.resolve(file);
  return resolved === root || resolved.startsWith(root + path.sep);
}

function resolveReportFile(urlPath) {
  let decoded = urlPath;
  try {
    decoded = decodeURIComponent(urlPath);
  } catch {
    return null;
  }
  const parts = decoded.split("/").filter(Boolean);
  if (parts.some((part) => part === "." || part === ".." || part.includes("\\"))) return null;
  let file = null;
  if (parts.length === 0 || (parts.length === 1 && parts[0] === dashboardFileName())) {
    file = path.join(outDir, dashboardFileName());
  }
  if (parts.length === 1 && CURRENT_FILE.test(parts[0])) file = path.join(outDir, parts[0]);
  if (parts.length === 3 && parts[0] === "archive" && parts[1] === safeRepoName(parts[1]) && ARCHIVED_FILE.test(parts[2]) && parts[2].startsWith(`${parts[1]}_report_`)) {
    file = path.join(outDir, "archive", parts[1], parts[2]);
  }
  if (!file || !insideOut(file) || !fs.existsSync(file)) return null;
  return file;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > 100_000) {
        reject(new Error("Request body is too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

async function handleRisk(req, res) {
  const raw = await readBody(req);
  const params = new URLSearchParams(raw);
  if (!tokenMatches(params.get("token"))) {
    send(res, 403, "The report token does not match. Scan the repository again.", "text/plain; charset=utf-8");
    return;
  }
  const { setRiskRating } = await import("./pipeline.mjs");
  try {
    const saved = setRiskRating({
      findingId: params.get("finding_id"),
      riskRating: params.get("risk_rating"),
      role: params.get("role"),
    });
    const wantsJson = (req.headers.accept || "").includes("application/json");
    if (wantsJson) {
      send(res, 200, JSON.stringify({ ok: true, risk_rating: saved.risk_rating, report: saved.report_file }), "application/json; charset=utf-8");
      return;
    }
    res.writeHead(303, { Location: `/${saved.report_file}`, ...corsHeaders() });
    res.end();
  } catch (error) {
    const status = /not found/i.test(error.message) ? 404 : 400;
    send(res, status, error.message, "text/plain; charset=utf-8");
  }
}

export function listenReportServer() {
  const server = http.createServer((req, res) => {
    if (req.method === "OPTIONS") {
      res.writeHead(204, corsHeaders());
      res.end();
      return;
    }
    const url = new URL(req.url || "/", reportServerOrigin());
    if (req.method === "GET" && url.pathname === "/health") {
      send(res, 200, "ok", "text/plain; charset=utf-8");
      return;
    }
    if (req.method === "POST" && url.pathname === "/risk") {
      handleRisk(req, res).catch((error) => {
        send(res, 500, error.message, "text/plain; charset=utf-8");
      });
      return;
    }
    if (req.method === "GET") {
      const file = resolveReportFile(url.pathname);
      if (!file) {
        const missingDashboard = url.pathname === "/" || url.pathname === `/${dashboardFileName()}`;
        send(res, 404, missingDashboard
          ? "Dashboard not found. Run node scan.mjs --dashboard."
          : "Report not found", "text/plain; charset=utf-8");
        return;
      }
      send(res, 200, fs.readFileSync(file), "text/html; charset=utf-8");
      return;
    }
    send(res, 405, "Method not allowed", "text/plain; charset=utf-8");
  });
  server.on("error", (error) => {
    process.stderr.write(`${error.message}\n`);
    process.exit(error.code === "EADDRINUSE" ? 0 : 1);
  });
  server.listen(reportServerPort, reportServerHost);
}

function probeHealth() {
  return new Promise((resolve) => {
    const req = http.get({
      hostname: reportServerHost,
      port: reportServerPort,
      path: "/health",
      timeout: 400,
    }, (res) => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => { body += chunk; });
      res.on("end", () => resolve(res.statusCode === 200 && body.trim() === "ok"));
    });
    req.on("error", () => resolve(false));
    req.on("timeout", () => {
      req.destroy();
      resolve(false);
    });
  });
}

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function ensureReportServer() {
  reportToken();
  if (await probeHealth()) return true;
  const child = spawn(process.execPath, [
    "--disable-warning=ExperimentalWarning",
    path.join(simRoot, "report-server.mjs"),
  ], {
    cwd: simRoot,
    detached: true,
    windowsHide: true,
    stdio: "ignore",
  });
  child.unref();
  for (let attempt = 0; attempt < 20; attempt += 1) {
    if (await probeHealth()) return true;
    await wait(100);
  }
  process.stderr.write("The risk dropdown could not reach the local report server at 127.0.0.1:47321.\n");
  return false;
}
