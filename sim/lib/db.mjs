import fs from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { dbPath, outDir } from "./paths.mjs";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS service (
  id text PRIMARY KEY,
  name text NOT NULL UNIQUE,
  data_class text NOT NULL CHECK (data_class IN ('public','internal','restricted')),
  gate_profile text NOT NULL DEFAULT 'standard',
  owner_team_id text NOT NULL
);
CREATE TABLE IF NOT EXISTS repo (
  id text PRIMARY KEY,
  name text NOT NULL,
  service_id text NOT NULL REFERENCES service(id)
);
CREATE TABLE IF NOT EXISTS scan (
  id text PRIMARY KEY,
  repo_id text NOT NULL REFERENCES repo(id),
  commit_sha text NOT NULL,
  rulepack_digest text NOT NULL,
  corpus_digest text NOT NULL,
  status text NOT NULL,
  snapshot_dir text,
  analyzers_json text NOT NULL DEFAULT '[]',
  created_at text NOT NULL DEFAULT (datetime('now')),
  report_role text,
  report_cache_hit integer,
  UNIQUE (repo_id, commit_sha, rulepack_digest, corpus_digest)
);
CREATE TABLE IF NOT EXISTS delivery (
  delivery_id text PRIMARY KEY,
  scan_id text NOT NULL REFERENCES scan(id)
);
CREATE TABLE IF NOT EXISTS code_unit (
  id text PRIMARY KEY,
  repo_id text NOT NULL,
  path text NOT NULL,
  qualified_name text NOT NULL,
  content_hash text NOT NULL,
  normalized text NOT NULL,
  sketch text NOT NULL,
  start_line integer NOT NULL,
  end_line integer NOT NULL,
  UNIQUE (repo_id, path, qualified_name, content_hash)
);
CREATE TABLE IF NOT EXISTS finding (
  id text PRIMARY KEY,
  scan_id text NOT NULL REFERENCES scan(id),
  code_unit_id text,
  class_id text NOT NULL,
  cwe text NOT NULL,
  risk_rating text NOT NULL,
  model_confidence real,
  calibrated_probability real,
  disposition text NOT NULL DEFAULT 'open',
  fingerprint text NOT NULL,
  gate text NOT NULL,
  factors text NOT NULL,
  system2 text NOT NULL DEFAULT 'not_run',
  evidence text NOT NULL,
  UNIQUE (scan_id, fingerprint)
);
CREATE TABLE IF NOT EXISTS adjudication (
  id text PRIMARY KEY,
  finding_id text NOT NULL REFERENCES finding(id),
  label text NOT NULL,
  actor_role text NOT NULL,
  created_at text NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS signature (
  feature_ref text PRIMARY KEY,
  id text NOT NULL UNIQUE,
  kind text NOT NULL CHECK (kind IN ('vulnerable','patched_twin','approved_control')),
  class_id text NOT NULL,
  corpus_version integer NOT NULL,
  sketch text NOT NULL,
  family text NOT NULL,
  provenance text NOT NULL,
  qualified_name text NOT NULL,
  content_hash text,
  normalized text,
  risk_rating text,
  rule_id text,
  source_repo text,
  source_path text
);
CREATE TABLE IF NOT EXISTS signature_match (
  code_unit_id text NOT NULL REFERENCES code_unit(id),
  signature_id text NOT NULL,
  similarity real NOT NULL,
  twin_similarity real,
  PRIMARY KEY (code_unit_id, signature_id)
);
CREATE TABLE IF NOT EXISTS waiver (
  id text PRIMARY KEY,
  fingerprint text NOT NULL,
  approver text NOT NULL,
  reason text NOT NULL,
  expires_at text NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_event (
  id text PRIMARY KEY,
  actor_role text NOT NULL,
  action text NOT NULL,
  detail text NOT NULL,
  created_at text NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS risk_override (
  fingerprint text PRIMARY KEY,
  risk_rating text NOT NULL CHECK (risk_rating IN ('critical','high','medium','low','info')),
  updated_at text NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS corpus_meta (
  id integer PRIMARY KEY CHECK (id = 1),
  version integer NOT NULL,
  digest text NOT NULL
);
`;

const SIGNATURE_COLUMNS = [
  ["content_hash", "text"],
  ["normalized", "text"],
  ["risk_rating", "text"],
  ["rule_id", "text"],
  ["source_repo", "text"],
  ["source_path", "text"],
];

function ensureColumns(db, table, columns) {
  const present = new Set(db.prepare(`PRAGMA table_info(${table})`).all().map((column) => column.name));
  for (const [name, type] of columns) {
    if (!present.has(name)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${name} ${type}`);
  }
}

function ensureSignatureColumns(db) {
  ensureColumns(db, "signature", SIGNATURE_COLUMNS);
  db.exec("CREATE UNIQUE INDEX IF NOT EXISTS signature_content_hash ON signature(content_hash);");
}

function ensureScanColumns(db) {
  ensureColumns(db, "scan", [
    ["report_role", "text"],
    ["report_cache_hit", "integer"],
  ]);
}

export function openDb() {
  fs.mkdirSync(outDir, { recursive: true });
  const db = new DatabaseSync(dbPath);
  db.exec("PRAGMA foreign_keys = ON;");
  db.exec(SCHEMA);
  ensureSignatureColumns(db);
  ensureScanColumns(db);
  const meta = db.prepare("SELECT version FROM corpus_meta WHERE id = 1").get();
  if (!meta) db.prepare("INSERT INTO corpus_meta (id, version, digest) VALUES (1, 1, '')").run();
  return db;
}
