import { CLASS_LABELS, RULES, describeFinding } from "./policy.mjs";
import { scrub } from "./redact.mjs";

const RISK_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const RISK_LABEL = { critical: "critical", high: "high", medium: "medium", low: "low", info: "informational" };
const RISK_OPTIONS = ["critical", "high", "medium", "low", "informational"];
const CONFIDENCE_ORDER = { high: 0, medium: 1, low: 2 };
const GATE_ORDER = { block: 0, comment: 1, clear: 2 };
const CONFIDENCE_RANGE = "0–1";

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function attr(value) {
  return escapeHtml(String(value).replace(/\s+/g, " ").trim());
}

function plural(count, noun) {
  return `${count} ${noun}${count === 1 ? "" : "s"}`;
}

function riskLabel(value) {
  return RISK_LABEL[value] || value || "";
}

function riskSelect(finding) {
  const current = riskLabel(finding.risk_rating);
  const options = RISK_OPTIONS.map((label) =>
    `<option value="${label}"${label === current ? " selected" : ""}>${label}</option>`).join("");
  return `<select class="risk-select risk-${escapeHtml(finding.risk_rating)}" data-finding="${escapeHtml(finding.id)}" aria-label="Risk rating">${options}</select>`;
}

function summaryText(findings, triage) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
  let suppressed = 0;
  for (const finding of findings) {
    const label = riskLabel(finding.risk_rating);
    if (counts[label] !== undefined) counts[label] += 1;
    if (finding.disposition === "suppressed" || finding.gate === "clear") suppressed += 1;
  }
  const risks = ["critical", "high", "medium", "low", "informational"].filter((risk) => counts[risk]);
  const parts = [risks.length ? risks.map((risk) => `${counts[risk]} ${risk}`).join(", ") : "No findings"];
  if (triage.vendor_files_skipped) {
    parts.push(`Skipped ${plural(triage.vendor_files_skipped, "vendor or generated file")}`);
  }
  if (triage.duplicates_removed) {
    parts.push(`Removed ${plural(triage.duplicates_removed, "duplicate hit")}`);
  }
  if (triage.weaker_removed) {
    parts.push(`Removed ${plural(triage.weaker_removed, "weaker SQL literal")} covered by a concatenation finding`);
  }
  if (suppressed) parts.push(plural(suppressed, "suppressed finding"));
  return `${parts.join(". ")}.`;
}

function orderedSites(evidence) {
  const sites = Array.isArray(evidence.sites) ? evidence.sites : [];
  return [...sites].sort((left, right) => (left.line - right.line) || ((left.column || 0) - (right.column || 0)));
}

function sitesContiguous(sites) {
  return sites.every((site, index) => {
    if (!index) return true;
    const previous = sites[index - 1].end_line || sites[index - 1].line;
    return site.line <= previous + 1;
  });
}

function whereText(evidence) {
  const sites = orderedSites(evidence);
  if (sites.length > 1 && sitesContiguous(sites)) {
    const start = sites[0].line;
    const end = sites[sites.length - 1].end_line || sites[sites.length - 1].line;
    const location = end > start ? `${evidence.path}:${start}-${end}` : `${evidence.path}:${start}`;
    const names = [...new Set(sites.map((site) => site.function_name).filter(Boolean))];
    return names.length === 1 ? `${location} · ${names[0]}` : location;
  }
  if (sites.length > 1) {
    return sites.map((site) => {
      const location = `${evidence.path}:${site.line}`;
      return site.function_name ? `${location} · ${site.function_name}` : location;
    }).join("; ");
  }
  const location = `${evidence.path || ""}:${evidence.line || ""}`;
  return evidence.function_name ? `${location} · ${evidence.function_name}` : location;
}

function codeText(evidence) {
  const sites = orderedSites(evidence);
  const snippets = sites.map((site) => site.snippet).filter(Boolean);
  if (snippets.length > 1) return snippets.join(sitesContiguous(sites) ? "\n" : "\n\n");
  return evidence.source_line || snippets[0] || "";
}

function similarSummary(factors) {
  if (!factors.likeness_candidate) return "";
  if (factors.likeness_provenance === "scan_observed") {
    const name = factors.likeness_function || "function";
    const repo = factors.likeness_repo || "a previous repository";
    return `Similar to ${name} in ${repo}`;
  }
  return `Similar to ${factors.likeness_family || factors.likeness_function || "a corpus sample"}`;
}

function similarCompare(row, colspan) {
  const { finding, described, note, where, code } = row;
  if (!note) return { toggle: "", extra: "" };
  const { factors, evidence } = finding;
  const similar = factors.similar || {};
  const classLabel = similar.classLabel || CLASS_LABELS[factors.likeness_class] || factors.likeness_class || "";
  const risk = riskLabel(similar.risk || factors.likeness_risk || "");
  const rating = [classLabel, risk].filter(Boolean).join(", ");
  const thisRating = [described.classLabel, riskLabel(finding.risk_rating)].filter(Boolean).join(", ");
  const likeness = `${factors.likeness_vulnerable ?? "none"} · patched twin ${factors.likeness_patched_twin ?? "none"}`;
  const tokens = (evidence.differing_tokens || []).filter(Boolean);
  const matchedCode = similar.code
    ? `<code>${escapeHtml(similar.code)}</code>`
    : `<span class="muted">The matched code is not in this database.</span>`;
  const tokenNote = tokens.length
    ? `<p class="muted compare-note">Differing tokens: ${escapeHtml(tokens.join(" "))}</p>`
    : "";
  return {
    toggle: `<button type="button" class="similar-toggle" aria-expanded="false">${escapeHtml(note)}</button>`,
    extra: `<tr class="similar-row" hidden><td colspan="${colspan}">
      <table class="compare">
        <thead><tr><th>Finding</th><th>Rating</th><th>Location</th><th>Code</th><th>Likeness</th></tr></thead>
        <tbody>
          <tr>
            <td>${escapeHtml(described.finding)}</td>
            <td>${escapeHtml(thisRating)}</td>
            <td>${escapeHtml(where)}</td>
            <td class="code"><code>${escapeHtml(code)}</code></td>
            <td></td>
          </tr>
          <tr>
            <td>${escapeHtml(similar.finding || note)}</td>
            <td>${escapeHtml(rating)}</td>
            <td>${escapeHtml(similar.where || "")}</td>
            <td class="code">${matchedCode}</td>
            <td>${escapeHtml(likeness)}</td>
          </tr>
        </tbody>
      </table>
      ${tokenNote}
    </td></tr>`,
  };
}

function likenessDetail(factors) {
  const scores = `Clone likeness: ${factors.likeness_vulnerable ?? "none"}. Patched twin: ${factors.likeness_patched_twin ?? "none"}.`;
  if (!factors.likeness_candidate) return scores;
  return `${scores} ${similarSummary(factors)}.`;
}

function englishList(items) {
  const values = [...new Set((items || []).map((item) => String(item || "").trim()).filter(Boolean))];
  if (values.length <= 1) return values[0] || "";
  if (values.length === 2) return `${values[0]} or ${values[1]}`;
  return `${values.slice(0, -1).join(", ")}, or ${values[values.length - 1]}`;
}

function whySentence(spec) {
  const basis = String(spec.confidenceBasis || "").trim();
  const looks = englishList(spec.sinkPatterns);
  const parts = [];
  if (basis) parts.push(basis.endsWith(".") ? basis : `${basis}.`);
  if (looks) parts.push(`It looks for ${looks}.`);
  return parts.join(" ");
}

function referenceLine(finding) {
  const parts = [];
  if (finding.cweList.length) parts.push(finding.cweList.join(", "));
  if (finding.factors.rule_id) parts.push(finding.factors.rule_id);
  if (finding.fingerprint) parts.push(`waiver id ${finding.fingerprint}`);
  return parts.join(" · ");
}

function triageDetail(finding) {
  const { evidence, factors } = finding;
  const spec = RULES[factors.rule_id];
  const blocks = [];
  if (factors.suppressed_by) blocks.push("<p>Cleared because it matched an approved control.</p>");
  if (factors.waived) blocks.push("<p>A waiver is active, so this comments instead of blocking.</p>");
  if (spec) {
    const why = whySentence(spec);
    const clears = englishList(spec.sanitizers);
    const blind = String(spec.limitations || "").trim();
    if (why) blocks.push(`<p><span class="k">Why.</span> ${escapeHtml(why)}</p>`);
    if (clears) blocks.push(`<p><span class="k">Clears when.</span> ${escapeHtml(clears)} is present.</p>`);
    if (blind) blocks.push(`<p><span class="k">Cannot see.</span> ${escapeHtml(blind)}</p>`);
  }
  if (factors.likeness_candidate) {
    const tokens = (evidence.differing_tokens || []).filter(Boolean);
    const differ = tokens.length ? ` Differing tokens: ${tokens.join(" ")}.` : "";
    blocks.push(`<p>${escapeHtml(`${similarSummary(factors)}. Likeness ${factors.likeness_vulnerable}. Patched twin ${factors.likeness_patched_twin}. This score does not set the gate.${differ}`)}</p>`);
  } else if (factors.likeness_vulnerable != null || factors.likeness_patched_twin != null) {
    blocks.push(`<p>${escapeHtml(likenessDetail(factors))}</p>`);
  }
  const reference = referenceLine(finding);
  if (reference) blocks.push(`<p class="muted">${escapeHtml(reference)}</p>`);
  return blocks.join("");
}

function describedFor(finding) {
  const { evidence, factors } = finding;
  const spec = RULES[factors.rule_id];
  if (!spec) {
    return {
      classLabel: finding.class_id || "",
      subclass: factors.taxonomy_id || "",
      finding: evidence.finding_name || evidence.title || factors.rule_id || finding.class_id || "",
      problem: evidence.problem || "",
    };
  }
  return describeFinding(spec, {
    pattern: factors.pattern,
    patterns: factors.patterns,
    ruleId: factors.rule_id,
    message: evidence.message,
    sourceLine: evidence.source_line,
    family: factors.likeness_family,
  });
}

function presentOptions(order, values) {
  const known = Object.keys(order);
  return [
    ...known.filter((value) => values.has(value)),
    ...[...values].filter((value) => !known.includes(value)).sort(),
  ];
}

function filterControl(key, label, options) {
  const name = escapeHtml(label);
  if (!options) {
    return `<input data-filter="${key}" aria-label="Filter ${name}" placeholder="Filter">`;
  }
  const choices = options.map((value) => `<option value="${escapeHtml(value)}">${escapeHtml(value)}</option>`).join("");
  return `<select data-filter="${key}" aria-label="Filter ${name}"><option value="">All</option>${choices}</select>`;
}

function formatScore(value) {
  if (value === null || value === undefined || value === "") return "";
  const n = Number(value);
  if (!Number.isFinite(n)) return "";
  const thousandths = Math.round(n * 1000) / 1000;
  const cents = Math.round(thousandths * 100) / 100;
  if (Math.abs(thousandths - cents) < 1e-9) return cents.toFixed(2);
  return thousandths.toFixed(3).replace(/0+$/, "");
}

function cacheText(value) {
  if (value === true) return "yes";
  if (value === false) return "no";
  return "not recorded";
}

function deploymentLabel(check) {
  if (check === "failure") return "Failed";
  if (check === "success") return "Passed";
  return String(check || "");
}

function metaField(label, valueHtml, hint) {
  return `<div class="field" tabindex="0"><dt>${escapeHtml(label)}<p class="hint" role="tooltip">${escapeHtml(hint)}</p></dt><dd>${valueHtml}</dd></div>`;
}

function analyzerItem(analyzer) {
  const status = String(analyzer.status || "");
  const kind = status.startsWith("ok") ? "ok" : status.startsWith("skipped") ? "skipped" : "other";
  return `<li><span class="dot dot-${kind}" aria-hidden="true"></span><span class="an-name">${escapeHtml(analyzer.name)}</span><span class="an-status">${escapeHtml(status)}</span></li>`;
}

export const reportThemeCss = `    :root {
      color-scheme: dark;
      --bg: #0d1117;
      --card: #161b22;
      --ink: #e6edf3;
      --muted: #8b949e;
      --line: #30363d;
      --soft: #21262d;
      --accent: #58a6ff;
      --accent-soft: #1c2d41;
      --panel: #0d1117;
      --critical: #f85149;
      --high: #db6d28;
      --medium: #d29922;
      --low: #388bfd;
      --info: #6e7681;
      --clear: #3fb950;
    }
    * { box-sizing: border-box; }
    body {
      font-family: "Segoe UI", system-ui, sans-serif;
      margin: 0;
      color: var(--ink);
      background: var(--bg);
      line-height: 1.45;
    }
    .page { max-width: 1440px; margin: 0 auto; padding: 1.4rem 1.25rem 2.5rem; }
    h1 { font-size: 1.45rem; font-weight: 650; letter-spacing: -0.02em; margin: 0 0 0.9rem; }
    h2 { font-size: 1.02rem; font-weight: 650; color: var(--ink); margin: 0 0 0.45rem; }
    h2 .count { font-size: 0.82rem; font-weight: 500; color: var(--muted); margin-left: 0.35rem; }
    a { color: var(--accent); }
    .card {
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 0.95rem 1.05rem 1.05rem;
    }
    .note { margin: 0 0 0.75rem; color: var(--muted); font-size: 0.86rem; }
    .tools { margin: 0 0 0.65rem; }
    .tools button, th button {
      font: inherit;
      color: var(--ink);
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 0.28rem 0.6rem;
      cursor: pointer;
    }
    .tools button:hover, th button:hover { background: var(--accent-soft); }
    th button { border: 0; background: none; border-radius: 6px; padding: 0; font-weight: 700; color: inherit; text-align: left; }
    .wrap { overflow-x: auto; container-type: inline-size; }
    table { border-collapse: collapse; width: 100%; background: var(--card); }
    th, td { padding: 0.48rem 0.55rem; text-align: left; font-size: 0.86rem; vertical-align: top; border-bottom: 1px solid var(--soft); }
    thead th { background: var(--soft); color: var(--muted); }
    th[aria-sort="ascending"] button::after { content: " ↑"; }
    th[aria-sort="descending"] button::after { content: " ↓"; }
    .filters th { background: var(--card); }
    .filters input, .filters select {
      width: 100%;
      box-sizing: border-box;
      font: inherit;
      font-size: 0.75rem;
      padding: 0.22rem 0.3rem;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--panel);
      color: var(--ink);
    }
    .muted { color: var(--muted); font-size: 0.8rem; }
    .chip {
      display: inline-block;
      padding: 0.08rem 0.48rem;
      border-radius: 999px;
      font-weight: 650;
      font-size: 0.78rem;
      text-transform: capitalize;
      letter-spacing: 0.01em;
    }
    .check { text-transform: none; }
    .risk-critical, .status-block, .check-failure { background: #3d1214; color: #ff7b72; }
    .risk-high { background: #3d220c; color: #f0883e; }
    .risk-medium, .status-comment { background: #3d2e0a; color: #e3b341; }
    .risk-low { background: #0d2847; color: #79c0ff; }
    .status-clear, .check-success { background: #0f2d1a; color: #56d364; }
    .risk-info { background: #21262d; color: #8b949e; }
    .charts { margin-top: 0.9rem; display: grid; grid-template-columns: 1fr 1fr; gap: 0.9rem; }
    .bars { list-style: none; margin: 0; padding: 0; display: grid; gap: 0.55rem; }
    .bars li { display: grid; grid-template-columns: 7.6rem 1fr 2rem; gap: 0.6rem; align-items: center; }
    .bar-label { color: var(--muted); font-size: 0.88rem; }
    .bar-track { height: 0.72rem; background: var(--soft); border-radius: 999px; overflow: hidden; }
    .bar-fill { display: block; height: 100%; border-radius: 999px; min-width: 0; }
    .bar-count { text-align: right; font-variant-numeric: tabular-nums; font-weight: 650; }
    .fill-critical, .fill-block { background: var(--critical); }
    .fill-high { background: var(--high); }
    .fill-medium, .fill-comment { background: var(--medium); }
    .fill-low { background: var(--low); }
    .fill-clear { background: var(--clear); }
    .fill-info { background: var(--info); }
    :focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
    @media (max-width: 860px) {
      .charts { grid-template-columns: 1fr; }
    }`;

export function barChart(title, note, rows, className = "") {
  const max = Math.max(...rows.map((row) => row.count), 0);
  const bars = rows.map((row) => {
    const width = max ? Math.round((row.count / max) * 1000) / 10 : 0;
    return `<li>
      <span class="bar-label">${escapeHtml(row.label)}</span>
      <span class="bar-track"><span class="bar-fill fill-${escapeHtml(row.key)}" style="width:${width}%"></span></span>
      <span class="bar-count">${row.count}</span>
    </li>`;
  }).join("");
  const extra = className ? ` ${escapeHtml(className)}` : "";
  return `<div class="chart card${extra}">
    <h2>${escapeHtml(title)}</h2>
    <p class="note">${escapeHtml(note)}</p>
    <ul class="bars">${bars}</ul>
  </div>`;
}

function archiveSection(archive) {
  const items = archive.map((item) =>
    `<li><a href="${escapeHtml(item.href)}">${escapeHtml(item.label)}</a></li>`).join("");
  return `<section class="history card" id="report-archive">
    <h2>Report archive</h2>
    <p class="note">Earlier versions of this report, with the date and time each one was saved.</p>
    ${items ? `<ul>${items}</ul>` : `<p class="muted">No earlier versions yet.</p>`}
  </section>`;
}

export function renderReport({ role, scan, findings, analyzers, archive = [], ratingUrl = "", ratingToken = "" }) {
  const showSecrets = role === "appsec";
  const showDetail = role === "appsec";
  const triage = analyzers.find((analyzer) => analyzer.name === "triage") || {};
  const visibleAnalyzers = analyzers.filter((analyzer) => analyzer.name !== "triage");
  const parsed = findings.map((finding) => ({
    ...finding,
    factors: JSON.parse(finding.factors),
    evidence: JSON.parse(finding.evidence),
    cweList: JSON.parse(finding.cwe || "[]"),
  }));
  parsed.sort((left, right) => {
    const risk = (RISK_ORDER[left.risk_rating] ?? 9) - (RISK_ORDER[right.risk_rating] ?? 9);
    if (risk) return risk;
    const pathOrder = String(left.evidence.path || "").localeCompare(String(right.evidence.path || ""));
    if (pathOrder) return pathOrder;
    return (left.evidence.line || 0) - (right.evidence.line || 0);
  });
  const view = parsed.map((finding) => {
    const described = describedFor(finding);
    const note = similarSummary(finding.factors);
    const band = finding.factors.rule_precision_band || "";
    const score = formatScore(finding.model_confidence);
    return {
      finding,
      described,
      note,
      where: whereText(finding.evidence),
      code: codeText(finding.evidence),
      confidence: band,
      confidenceText: score ? `${band} (${score})` : band,
      next: finding.evidence.next_step || "",
    };
  });
  const classes = [...new Set(view.map((row) => row.described.classLabel).filter(Boolean))].sort();
  const subclasses = [...new Set(view.map((row) => row.described.subclass).filter(Boolean))].sort();
  const presentRisks = new Set(view.map((row) => riskLabel(row.finding.risk_rating)).filter(Boolean));
  const risks = RISK_OPTIONS.filter((label) => presentRisks.has(label));
  const confidence = presentOptions(CONFIDENCE_ORDER, new Set(view.map((row) => row.confidence).filter(Boolean)));
  const gates = presentOptions(GATE_ORDER, new Set(view.map((row) => row.finding.gate).filter(Boolean)));
  const columnDefs = [
    { key: "risk", label: "Risk", options: risks },
    { key: "class", label: "Class", options: classes },
    { key: "subclass", label: "Subclass", options: subclasses },
    { key: "finding", label: "Finding" },
    { key: "problem", label: "Problem" },
    { key: "where", label: "Location" },
    { key: "code", label: "Code" },
    { key: "confidence", label: `Confidence (${CONFIDENCE_RANGE})`, options: confidence },
    { key: "next", label: "Next step" },
    { key: "gate", label: "Pull Status", options: gates },
  ];
  const header = columnDefs.map((column) =>
    `<th data-sort="${column.key}" aria-sort="none"><button type="button">${escapeHtml(column.label)}</button></th>`).join("");
  const filters = columnDefs.map((column) =>
    `<th>${filterControl(column.key, column.label, column.options)}</th>`).join("");
  const rows = view.map((row) => {
    const { finding, described, note } = row;
    const { evidence } = finding;
    const secret = showSecrets && evidence.secretPreview
      ? `<div class="muted">Secret preview: ${escapeHtml(evidence.secretPreview)}</div>`
      : "";
    const detail = showDetail ? `<tr class="detail"><td colspan="${columnDefs.length}"><details>
      <summary>Why this fired</summary>
      <div class="triage">${triageDetail(finding)}</div>
    </details></td></tr>` : "";
    const findingText = `${described.finding}${note ? ` ${note}` : ""}`;
    const similar = similarCompare(row, columnDefs.length);
    const rank = RISK_ORDER[finding.risk_rating] ?? 9;
    const confidenceRank = CONFIDENCE_ORDER[row.confidence] ?? 9;
    const gateRank = GATE_ORDER[finding.gate] ?? 9;
    return `<tbody class="finding" data-risk="${attr(riskLabel(finding.risk_rating))}" data-risk-rank="${rank}" data-class="${attr(described.classLabel)}" data-subclass="${attr(described.subclass)}" data-finding="${attr(findingText)}" data-problem="${attr(described.problem)}" data-where="${attr(row.where)}" data-code="${attr(row.code)}" data-confidence="${attr(row.confidence)}" data-confidence-rank="${confidenceRank}" data-next="${attr(row.next)}" data-gate="${attr(finding.gate)}" data-gate-rank="${gateRank}">
    <tr>
      <td>${riskSelect(finding)}</td>
      <td>${escapeHtml(described.classLabel)}</td>
      <td class="subclass">${escapeHtml(described.subclass)}</td>
      <td>${escapeHtml(described.finding)}${similar.toggle}</td>
      <td class="problem">${escapeHtml(described.problem)}</td>
      <td class="where">${escapeHtml(row.where)}</td>
      <td class="code"><code>${escapeHtml(row.code)}</code>${secret}</td>
      <td>${escapeHtml(row.confidenceText)}</td>
      <td>${escapeHtml(row.next)}</td>
      <td><span class="chip status-${escapeHtml(finding.gate)}">${escapeHtml(finding.gate)}</span></td>
    </tr>${similar.extra}${detail}
    </tbody>`;
  }).join("");
  const riskCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const gateCounts = { block: 0, comment: 0, clear: 0 };
  for (const finding of parsed) {
    if (riskCounts[finding.risk_rating] !== undefined) riskCounts[finding.risk_rating] += 1;
    if (gateCounts[finding.gate] !== undefined) gateCounts[finding.gate] += 1;
  }
  const riskRows = ["critical", "high", "medium", "low"]
    .concat(riskCounts.info ? ["info"] : [])
    .map((key) => ({ key, label: riskLabel(key), count: riskCounts[key] }));
  const gateRows = [
    { key: "block", label: "block", count: gateCounts.block },
    { key: "comment", label: "comment", count: gateCounts.comment },
    { key: "clear", label: "cleared", count: gateCounts.clear },
  ];
  const analyzerRows = visibleAnalyzers.length
    ? visibleAnalyzers.map(analyzerItem).join("")
    : `<li class="empty-analyzer">No analyzers recorded.</li>`;
  const repoLine = scan.repo_name
    ? metaField("Repository", escapeHtml(scan.repo_name), "The repository this scan reviewed.")
    : "";
  const reportLine = scan.report_file
    ? metaField("Report", escapeHtml(scan.report_file), "This scan's report file. Earlier versions are listed at the bottom with the date and time they were saved.")
    : "";
  const empty = view.length
    ? rows
    : `<tbody class="empty"><tr><td colspan="${columnDefs.length}">No findings.</td></tr></tbody>`;
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Code review simulation</title>
  <style>
${reportThemeCss}
    .top {
      display: grid;
      grid-template-columns: minmax(0, 1.55fr) minmax(16rem, 0.72fr);
      gap: 0.9rem;
      align-items: stretch;
    }
    .lead { display: grid; gap: 0.85rem; align-content: start; }
    .saved { margin: 0 0 0.75rem; color: var(--muted); font-size: 0.86rem; }
    .meta { display: grid; gap: 0.32rem; margin: 0; }
    .meta .field { position: relative; display: grid; grid-template-columns: 7.6rem minmax(0, 1fr); gap: 0.75rem; align-items: start; cursor: help; }
    .field:hover, .field:focus-within { z-index: 5; }
    .meta dt {
      color: var(--muted);
      font-size: 0.82rem;
      padding-top: 0.08rem;
      width: fit-content;
      border-bottom: 1px dotted var(--muted);
      cursor: help;
    }
    .meta dd { margin: 0; overflow-wrap: anywhere; }
    .hint {
      display: none;
      position: absolute;
      z-index: 4;
      left: 0;
      top: calc(100% + 0.2rem);
      width: max-content;
      max-width: 22rem;
      margin: 0;
      padding: 0.45rem 0.6rem;
      background: #1c2128;
      color: var(--ink);
      border: 1px solid var(--line);
      border-radius: 8px;
      font-size: 0.78rem;
      line-height: 1.35;
      box-shadow: 0 10px 28px rgba(0, 0, 0, 0.55);
    }
    .field:hover .hint, .field:focus-within .hint { display: block; }
    .summary { margin: 0; }
    .analyzers { list-style: none; margin: 0; padding: 0; }
    .analyzers li {
      display: grid;
      grid-template-columns: 0.55rem 1fr;
      column-gap: 0.55rem;
      row-gap: 0.05rem;
      padding: 0.4rem 0;
      border-bottom: 1px solid var(--soft);
    }
    .analyzers li:last-child { border-bottom: 0; padding-bottom: 0; }
    .an-name { font-weight: 650; }
    .an-status { grid-column: 2; color: var(--muted); font-size: 0.84rem; }
    .empty-analyzer { color: var(--muted); display: block; }
    .dot { width: 0.5rem; height: 0.5rem; border-radius: 50%; margin-top: 0.38rem; }
    .dot-ok { background: var(--clear); }
    .dot-skipped { background: var(--info); }
    .dot-other { background: var(--accent); }
    .findings, .history { margin-top: 0.9rem; }
    .history ul { margin: 0; padding-left: 1.15rem; }
    .history li { margin: 0.28rem 0; }
    .back { margin: 0.7rem 0 0; }
    table { min-width: 68rem; }
    .problem { min-width: 12rem; }
    .code { min-width: 18rem; }
    td:last-child { min-width: 6.2rem; }
    tbody.finding:hover td { background: var(--soft); }
    code {
      font-family: Consolas, "Courier New", monospace;
      font-size: 0.8rem;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      background: var(--panel);
      color: var(--ink);
      border-radius: 4px;
      padding: 0.12rem 0.28rem;
    }
    .where { white-space: normal; }
    .risk-select {
      font: inherit;
      font-weight: 650;
      font-size: 0.78rem;
      border-radius: 999px;
      border: 1px solid transparent;
      padding: 0.12rem 0.35rem;
      cursor: pointer;
      max-width: 9.8rem;
    }
    .risk-select:disabled { cursor: progress; opacity: 0.7; }
    .subclass { font-weight: 650; }
    tbody.finding[hidden] { display: none; }
    details { margin: 0; }
    summary { cursor: pointer; color: var(--ink); }
    .similar-toggle {
      display: block;
      margin-top: 0.28rem;
      padding: 0;
      border: 0;
      background: none;
      color: var(--muted);
      font: inherit;
      font-size: 0.8rem;
      text-align: left;
      cursor: pointer;
      width: fit-content;
    }
    .similar-toggle:hover { color: var(--accent); }
    .similar-row > td { background: #10151c; padding: 0.75rem 0.7rem 0.9rem; }
    table.compare {
      min-width: 0;
      width: min(100%, calc(100cqw - 1.4rem));
      position: sticky;
      left: 0.7rem;
      background: transparent;
    }
    table.compare th:nth-child(4), table.compare td:nth-child(4) { width: 46%; }
    table.compare th:nth-child(5), table.compare td:nth-child(5) { white-space: nowrap; }
    .compare-note { margin: 0.45rem 0 0; }
    .triage { display: grid; gap: 0.35rem; margin-top: 0.45rem; }
    .triage p { margin: 0; }
    .triage .k { font-weight: 650; }
    @media (max-width: 860px) {
      .top { grid-template-columns: 1fr; }
      .where { white-space: normal; }
    }
  </style>
</head>
<body data-role="${escapeHtml(role)}" data-rating-url="${escapeHtml(ratingUrl)}" data-rating-token="${escapeHtml(ratingToken)}">
  <div class="page">
    <h1>Code review simulation</h1>
    <div class="top">
      <div class="lead">
        <section class="card">
          <dl class="meta">
            ${repoLine}
            ${reportLine}
            ${metaField("Role", escapeHtml(role), "Who is viewing this report. AppSec also sees why a check fired and redacted secret previews.")}
            ${metaField("Deployment", `<span class="chip check check-${escapeHtml(scan.check)}">${escapeHtml(deploymentLabel(scan.check))}</span>`, "Failed or Passed. Failed means at least one finding blocks deployment. Passed means none do.")}
            ${metaField("Why", escapeHtml(scan.check_reason || ""), "The reason this deployment failed or passed.")}
            ${metaField("Data class", escapeHtml(scan.data_class || ""), "How sensitive the service is: public, internal, or restricted. Restricted can turn a high finding into a block.")}
            ${metaField("Cache hit", escapeHtml(cacheText(scan.cache_hit)), "Yes or no. Yes means this commit was already scanned with the same rules, so the analyzers did not run again.")}
            ${metaField("System 2", escapeHtml(scan.system2), "The model review. Not run means only the rule checks produced these findings.")}
            ${metaField("Corpus", escapeHtml(scan.corpus_digest), "The set of known-vulnerable samples this scan was compared with.")}
            ${metaField("Commit", escapeHtml(scrub(scan.commit_sha)), "The commit that was scanned.")}
          </dl>
        </section>
        <section class="card">
          <h2>Summary</h2>
          <p class="summary">${escapeHtml(summaryText(parsed, triage))}</p>
        </section>
      </div>
      <aside class="card">
        <h2>Analyzers</h2>
        <ul class="analyzers">${analyzerRows}</ul>
      </aside>
    </div>
    <section class="findings card">
      <h2>Findings <span id="finding-count" class="count"></span></h2>
      <p class="note">Choose a risk rating to save it in the local database. The choices are informational, low, medium, high, and critical.</p>
      <p id="risk-status" class="note" role="status"></p>
      <p class="tools"><button type="button" id="clear-filters">Clear filters</button></p>
      <div class="wrap">
      <table id="findings">
        <thead>
          <tr>${header}</tr>
          <tr class="filters">${filters}</tr>
        </thead>
        ${empty}
      </table>
      </div>
    </section>
    <section class="charts">
      ${barChart("Risk", "Findings in each risk classification.", riskRows)}
      ${barChart("Pull status", "Findings that block, comment, or were cleared.", gateRows)}
    </section>
    ${archiveSection(archive)}
  </div>
  <script>
    (function () {
      document.querySelectorAll(".risk-select").forEach((select) => {
        select.dataset.saved = select.value;
        select.addEventListener("change", () => {
          const status = document.getElementById("risk-status");
          const url = document.body.getAttribute("data-rating-url") || "";
          if (!url) {
            select.value = select.dataset.saved || select.value;
            if (status) status.textContent = "This report has no save address.";
            return;
          }
          if (status) status.textContent = "Saving rating…";
          select.disabled = true;
          const form = document.createElement("form");
          form.method = "POST";
          form.action = url;
          const fields = {
            finding_id: select.getAttribute("data-finding") || "",
            risk_rating: select.value,
            role: document.body.getAttribute("data-role") || "",
            token: document.body.getAttribute("data-rating-token") || "",
          };
          for (const [name, value] of Object.entries(fields)) {
            const input = document.createElement("input");
            input.type = "hidden";
            input.name = name;
            input.value = value;
            form.appendChild(input);
          }
          document.body.appendChild(form);
          form.submit();
        });
      });
      const table = document.getElementById("findings");
      if (!table) return;
      table.querySelectorAll(".similar-toggle").forEach((button) => {
        button.addEventListener("click", () => {
          const panel = button.closest("tbody") && button.closest("tbody").querySelector(".similar-row");
          if (!panel) return;
          const open = panel.hasAttribute("hidden");
          panel.toggleAttribute("hidden", !open);
          button.setAttribute("aria-expanded", open ? "true" : "false");
        });
      });
      const headers = [...table.querySelectorAll("thead th[data-sort]")];
      const count = document.getElementById("finding-count");
      const clear = document.getElementById("clear-filters");
      let sortKey = "risk";
      let sortDir = 1;
      function groups() {
        return [...table.querySelectorAll("tbody.finding")];
      }
      function compare(left, right) {
        const leftRank = left.getAttribute("data-" + sortKey + "-rank");
        const rightRank = right.getAttribute("data-" + sortKey + "-rank");
        if (leftRank !== null && rightRank !== null) return (Number(leftRank) - Number(rightRank)) * sortDir;
        const leftText = left.getAttribute("data-" + sortKey) || "";
        const rightText = right.getAttribute("data-" + sortKey) || "";
        return leftText.localeCompare(rightText, undefined, { numeric: true, sensitivity: "base" }) * sortDir;
      }
      function apply() {
        const filters = {};
        table.querySelectorAll("[data-filter]").forEach((input) => {
          filters[input.getAttribute("data-filter")] = input.value.trim().toLowerCase();
        });
        const rows = groups().sort(compare);
        let shown = 0;
        for (const row of rows) {
          table.appendChild(row);
          const hide = Object.entries(filters).some(([key, query]) => {
            if (!query) return false;
            return !(row.getAttribute("data-" + key) || "").toLowerCase().includes(query);
          });
          row.hidden = hide;
          if (!hide) shown += 1;
        }
        if (count) {
          const total = rows.length;
          count.textContent = shown === total ? (total === 1 ? "1 finding" : total + " findings") : "Showing " + shown + " of " + total;
        }
        headers.forEach((headerCell) => {
          const key = headerCell.getAttribute("data-sort");
          headerCell.setAttribute("aria-sort", key === sortKey ? (sortDir === 1 ? "ascending" : "descending") : "none");
        });
      }
      headers.forEach((headerCell) => {
        const button = headerCell.querySelector("button");
        if (!button) return;
        button.addEventListener("click", () => {
          const key = headerCell.getAttribute("data-sort");
          if (sortKey === key) sortDir *= -1;
          else {
            sortKey = key;
            sortDir = 1;
          }
          apply();
        });
      });
      table.querySelectorAll("[data-filter]").forEach((input) => {
        input.addEventListener("input", apply);
        input.addEventListener("change", apply);
      });
      if (clear) {
        clear.addEventListener("click", () => {
          table.querySelectorAll("[data-filter]").forEach((input) => { input.value = ""; });
          apply();
        });
      }
      apply();
    }());
  </script>
</body>
</html>`;
}
