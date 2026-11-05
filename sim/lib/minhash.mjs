const KEYWORDS = new Set([
  "function", "return", "const", "let", "var", "if", "else", "for", "while",
  "new", "typeof", "import", "from", "export", "async", "await", "class",
  "extends", "try", "catch", "throw", "of", "in", "true", "false", "null",
  "undefined", "default", "case", "switch", "break", "continue",
]);

export function normalizeTokens(source) {
  const stripped = source
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/\/\/[^\n]*/g, " ");
  const raw = stripped.match(/[A-Za-z_][A-Za-z0-9_]*|"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|==|!=|&&|\|\||=>|[0-9]+|[^\s]/g) || [];
  return raw.map((token) => {
    if (KEYWORDS.has(token)) return token;
    if (token.startsWith('"') || token.startsWith("'")) return token;
    if (/^[A-Za-z_]/.test(token)) return "VAR";
    return token;
  });
}

function fnv(text, seed) {
  let hash = (0x811c9dc5 ^ seed) >>> 0;
  for (let i = 0; i < text.length; i += 1) {
    hash ^= text.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash >>> 0;
}

export function sketchOf(tokens, hashCount = 64) {
  const shingles = [];
  if (tokens.length < 3) shingles.push(tokens.join("\u0001"));
  else {
    for (let i = 0; i <= tokens.length - 3; i += 1) {
      shingles.push(tokens.slice(i, i + 3).join("\u0001"));
    }
  }
  const sketch = new Array(hashCount);
  for (let seed = 0; seed < hashCount; seed += 1) {
    let min = 0xffffffff;
    for (const shingle of shingles) {
      const hash = fnv(shingle, seed + 1);
      if (hash < min) min = hash;
    }
    sketch[seed] = min;
  }
  return sketch;
}

export function similarity(left, right) {
  const width = Math.min(left.length, right.length);
  if (!width) return 0;
  let same = 0;
  for (let i = 0; i < width; i += 1) if (left[i] === right[i]) same += 1;
  return same / width;
}

export function differingTokens(left, right, limit = 8) {
  const rightSet = new Set(right);
  const leftSet = new Set(left);
  const onlyLeft = left.filter((token) => !rightSet.has(token));
  const onlyRight = right.filter((token) => !leftSet.has(token));
  return [...onlyLeft, ...onlyRight].slice(0, limit);
}
