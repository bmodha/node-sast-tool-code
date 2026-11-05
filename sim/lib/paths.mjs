import path from "node:path";
import { fileURLToPath } from "node:url";

export const simRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
export const outDir = path.join(simRoot, "out");
export const dbPath = path.join(outDir, "review.sqlite");
export const corpusDir = path.join(simRoot, "corpus");
export const policyPath = path.join(simRoot, "policy.json");
export const eslintConfigPath = path.join(simRoot, "eslint.config.js");
export const localRulesPath = path.join(simRoot, "eslint-rules", "local-security.js");
export const analyzersPath = path.join(simRoot, "lib", "analyzers.mjs");
export const advisoriesPath = path.join(simRoot, "advisories.json");
