const BANNED = new Set(["snippet", "patch", "secret", "Secret", "Match", "body"]);

export function scrub(value) {
  return String(value).replace(/AKIA[0-9A-Z]{16}/g, "AKIA…");
}

export function previewSecret(secret) {
  const text = String(secret);
  if (text.length <= 4) return "…";
  return `${text.slice(0, 4)}…`;
}

export function safeDetail(input) {
  const output = {};
  for (const [key, value] of Object.entries(input || {})) {
    if (BANNED.has(key)) continue;
    output[key] = typeof value === "string" ? scrub(value) : value;
  }
  return output;
}
