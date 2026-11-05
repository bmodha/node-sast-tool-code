import { spawnSync } from "node:child_process";
import path from "node:path";
import { createHash } from "node:crypto";
import { helpText } from "./lib/help.mjs";
import { openDb } from "./lib/db.mjs";
import { writeDashboard } from "./lib/dashboard.mjs";
import { ensureReportServer } from "./lib/report-server.mjs";
import { runScan } from "./lib/pipeline.mjs";

function parseArgs(argv) {
  const args = { as: "developer", event: "", source: "", dataClass: "internal", help: false, dashboard: false };
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === "--help") args.help = true;
    else if (argv[i] === "--as") args.as = argv[++i];
    else if (argv[i] === "--event") args.event = argv[++i];
    else if (argv[i] === "--source") args.source = argv[++i];
    else if (argv[i] === "--data-class") args.dataClass = argv[++i];
    else if (argv[i] === "--dashboard") args.dashboard = true;
  }
  return args;
}

function commitOf(dir) {
  const result = spawnSync("git", ["rev-parse", "HEAD"], { cwd: dir, encoding: "utf8", windowsHide: true });
  if (result.status === 0 && result.stdout.trim()) return result.stdout.trim();
  return createHash("sha256").update(path.resolve(dir)).digest("hex").slice(0, 12);
}

function eventFromSource(source, dataClass) {
  const root = path.resolve(source);
  const slug = path.basename(root).replace(/[^A-Za-z0-9._-]/g, "-") || "repo";
  const stamp = createHash("sha256").update(root).digest("hex").slice(0, 8);
  const name = `${slug}-${stamp}`;
  const sha = commitOf(root);
  return {
    delivery_id: `${name}:${sha}:${Date.now()}`,
    repo_id: `repo-${name}`,
    repo_name: slug,
    service_id: `svc-${name}`,
    service_name: `local-${name}`,
    owner_team_id: "local",
    data_class: dataClass,
    commit_sha: sha,
    source_dir: root,
    external: true,
  };
}

const args = parseArgs(process.argv.slice(2));
if (args.help) {
  process.stdout.write(helpText());
  process.exit(0);
}
if (args.dashboard && !args.event && !args.source) {
  const db = openDb();
  try {
    const file = writeDashboard(db);
    process.stderr.write(`Dashboard written to ${file}\n`);
  } finally {
    db.close();
  }
  await ensureReportServer();
  process.stderr.write("Open dashboard.html from that folder, or http://127.0.0.1:47321/\n");
  process.exit(0);
}
if (!args.event && !args.source) {
  process.stderr.write("Usage: node scan.mjs --event <file> | --source <path> --as <role> | --dashboard\nRun node scan.mjs --help for every command and check.\n");
  process.exit(1);
}
if (!["public", "internal", "restricted"].includes(args.dataClass)) {
  process.stderr.write("data-class must be public, internal, or restricted\n");
  process.exit(1);
}

try {
  await ensureReportServer();
  const result = args.source
    ? await runScan({ event: eventFromSource(args.source, args.dataClass), role: args.as })
    : await runScan({ eventPath: args.event, role: args.as });
  process.stderr.write(`Report written to ${result.report_path}\n`);
  process.stderr.write(`Open ${result.report_file} from that folder, or http://127.0.0.1:47321/${result.report_file} to change risk ratings.\n`);
  process.stdout.write(`${JSON.stringify(result)}\n`);
} catch (error) {
  process.stderr.write(`${error.message}\n`);
  process.exit(1);
}
