function sliceFunction(source, start) {
  const brace = source.indexOf("{", start);
  if (brace < 0) return null;
  let depth = 0;
  let end = source.length;
  for (let i = brace; i < source.length; i += 1) {
    if (source[i] === "{") depth += 1;
    else if (source[i] === "}") {
      depth -= 1;
      if (depth === 0) {
        end = i + 1;
        break;
      }
    }
  }
  return {
    body: source.slice(start, end),
    line: source.slice(0, start).split("\n").length,
    endLine: source.slice(0, end).split("\n").length,
  };
}

const PATTERNS = [
  /function\s+([A-Za-z0-9_]+)\s*\([^)]*\)\s*\{/g,
  /(?:module\.exports|exports)\.([A-Za-z0-9_]+)\s*=\s*function\s*\([^)]*\)\s*\{/g,
];

export function extractFunctions(source) {
  const units = [];
  const seen = new Set();
  for (const pattern of PATTERNS) {
    pattern.lastIndex = 0;
    let match = pattern.exec(source);
    while (match) {
      const sliced = sliceFunction(source, match.index);
      const key = `${match.index}:${match[1]}`;
      if (sliced && !seen.has(key)) {
        seen.add(key);
        units.push({ name: match[1], ...sliced });
      }
      match = pattern.exec(source);
    }
  }
  units.sort((a, b) => a.line - b.line || a.name.localeCompare(b.name));
  return units;
}
