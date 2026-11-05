import fs from "node:fs";
import { CLASS_LABELS, checkFromFindings } from "./policy.mjs";
import { outDir } from "./paths.mjs";
import { dashboardPath, reportFileName, reportPathFor } from "./report-files.mjs";
import { barChart, reportThemeCss } from "./report.mjs";

const RISK_KEYS = ["critical", "high", "medium", "low", "info"];
const RISK_LETTER = { critical: "C", high: "H", medium: "M", low: "L", info: "I" };
const RISK_LABEL = { critical: "critical", high: "high", medium: "medium", low: "low", info: "informational" };
const SEVERITY_WEIGHT = { critical: 100000000, high: 1000000, medium: 10000, low: 100, info: 1 };

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function deploymentLabel(check) {
  if (check === "failure") return "Failed";
  if (check === "success") return "Passed";
  return String(check || "");
}

function countFindings(findings) {
  const risk = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const gate = { block: 0, comment: 0, clear: 0 };
  const classes = new Map();
  for (const finding of findings) {
    if (risk[finding.risk_rating] !== undefined) risk[finding.risk_rating] += 1;
    if (gate[finding.gate] !== undefined) gate[finding.gate] += 1;
    const key = finding.class_id || "";
    classes.set(key, (classes.get(key) || 0) + 1);
  }
  return { risk, gate, classes };
}

function severityRank(counts) {
  return RISK_KEYS.reduce((total, key) => total + counts[key] * SEVERITY_WEIGHT[key], 0);
}

function severityText(counts) {
  return RISK_KEYS.map((key) => `${counts[key]}${RISK_LETTER[key]}`).join(" ");
}

function severityChips(counts) {
  const chips = RISK_KEYS.map((key) => {
    const zero = counts[key] ? "" : " zero";
    return `<span class="chip risk-${key}${zero}">${counts[key]}${RISK_LETTER[key]}</span>`;
  }).join("");
  return `<span class="sev">${chips}</span>`;
}

function uniqueValues(values) {
  return [...new Set(values.filter(Boolean))].sort((left, right) =>
    left.localeCompare(right, undefined, { sensitivity: "base" }));
}

function selectOptions(pairs) {
  const options = pairs.map(([value, label]) =>
    `<option value="${escapeHtml(value)}">${escapeHtml(label)}</option>`).join("");
  return `<option value="">All</option>${options}`;
}

function loadRows(db) {
  const scans = db.prepare(`SELECT s.id, s.created_at, s.report_role, r.name AS repo_name,
      svc.data_class, svc.owner_team_id
    FROM scan s
    JOIN repo r ON r.id = s.repo_id
    JOIN service svc ON svc.id = r.service_id
    WHERE s.rowid = (
      SELECT s2.rowid FROM scan s2
      WHERE s2.repo_id = s.repo_id
      ORDER BY s2.created_at DESC, s2.rowid DESC
      LIMIT 1
    )`).all().filter((scan) => fs.existsSync(reportPathFor(scan.repo_name)));
  const byScan = new Map();
  if (scans.length) {
    const marks = scans.map(() => "?").join(", ");
    const findings = db.prepare(
      `SELECT scan_id, risk_rating, gate, class_id FROM finding WHERE scan_id IN (${marks})`,
    ).all(...scans.map((scan) => scan.id));
    for (const finding of findings) {
      if (!byScan.has(finding.scan_id)) byScan.set(finding.scan_id, []);
      byScan.get(finding.scan_id).push(finding);
    }
  }
  const rows = scans.map((scan) => {
    const findings = byScan.get(scan.id) || [];
    const counted = countFindings(findings);
    return {
      repoName: scan.repo_name,
      reportFile: reportFileName(scan.repo_name),
      total: findings.length,
      counts: counted.risk,
      blocking: counted.gate.block,
      gate: counted.gate,
      classes: counted.classes,
      check: checkFromFindings(findings),
      dataClass: scan.data_class || "",
      reviewer: scan.report_role || "not recorded",
      owner: scan.owner_team_id || "",
      scanned: scan.created_at || "",
    };
  });
  rows.sort((left, right) => {
    const deploy = (left.check === "failure" ? 0 : 1) - (right.check === "failure" ? 0 : 1);
    if (deploy) return deploy;
    if (right.blocking !== left.blocking) return right.blocking - left.blocking;
    return left.repoName.localeCompare(right.repoName, undefined, { numeric: true, sensitivity: "base" });
  });
  return rows;
}

function sumCounts(rows, keys, pick) {
  const totals = Object.fromEntries(keys.map((key) => [key, 0]));
  for (const row of rows) {
    const source = pick(row);
    for (const key of keys) totals[key] += source[key] || 0;
  }
  return totals;
}

function stackedChart(rows) {
  const ordered = [...rows].sort((left, right) =>
    right.total - left.total
    || left.repoName.localeCompare(right.repoName, undefined, { numeric: true, sensitivity: "base" }));
  const max = Math.max(...ordered.map((row) => row.total), 0);
  const items = ordered.map((row) => {
    const segments = RISK_KEYS.map((key) => {
      const count = row.counts[key];
      if (!count || !max) return "";
      const width = Math.round((count / max) * 1000) / 10;
      return `<span class="bar-fill fill-${key}" style="flex:0 0 ${width}%"></span>`;
    }).join("");
    return `<li>
      <span class="bar-label" title="${escapeHtml(row.repoName)}">${escapeHtml(row.repoName)}</span>
      <span class="bar-track"><span class="stack">${segments}</span></span>
      <span class="bar-count">${row.total}</span>
    </li>`;
  }).join("");
  const legend = RISK_KEYS.map((key) =>
    `<span><span class="swatch fill-${key}"></span>${escapeHtml(RISK_LABEL[key])}</span>`).join("");
  const body = items
    ? `<ul class="bars stacks">${items}</ul><p class="legend">${legend}</p>`
    : `<p class="muted">No reports yet.</p>`;
  return `<div class="chart card chart-wide">
    <h2>Severity by repository</h2>
    <p class="note">Each bar is that report's findings, split by risk. Longer bars have more findings.</p>
    ${body}
  </div>`;
}

function statCard(value, label, valueClass = "stat-value") {
  return `<article class="card stat">
    <p class="${valueClass}">${value}</p>
    <p class="stat-label">${escapeHtml(label)}</p>
  </article>`;
}

function renderDashboard(rows) {
  const findings = rows.reduce((total, row) => total + row.total, 0);
  const blocking = rows.reduce((total, row) => total + row.blocking, 0);
  const failed = rows.filter((row) => row.check === "failure").length;
  const riskTotals = sumCounts(rows, RISK_KEYS, (row) => row.counts);
  const gateTotals = sumCounts(rows, ["block", "comment", "clear"], (row) => row.gate);
  const classTotals = new Map();
  for (const row of rows) {
    for (const [key, count] of row.classes) {
      const label = CLASS_LABELS[key] || key || "Unknown";
      classTotals.set(label, (classTotals.get(label) || 0) + count);
    }
  }
  const riskRows = ["critical", "high", "medium", "low"]
    .concat(riskTotals.info ? ["info"] : [])
    .map((key) => ({ key, label: RISK_LABEL[key], count: riskTotals[key] }));
  const deployRows = [
    { key: "block", label: "Failed", count: failed },
    { key: "clear", label: "Passed", count: rows.length - failed },
  ];
  const classRows = [...classTotals.entries()]
    .map(([label, count]) => ({ key: "accent", label, count }))
    .sort((left, right) => right.count - left.count || left.label.localeCompare(right.label));
  const gateRows = [
    { key: "block", label: "block", count: gateTotals.block },
    { key: "comment", label: "comment", count: gateTotals.comment },
    { key: "clear", label: "cleared", count: gateTotals.clear },
  ];
  const deployOptions = [];
  if (rows.some((row) => row.check === "failure")) deployOptions.push(["failed", "Failed"]);
  if (rows.some((row) => row.check !== "failure")) deployOptions.push(["passed", "Passed"]);
  const filters = {
    class: selectOptions(uniqueValues(rows.map((row) => row.dataClass)).map((value) => [value, value])),
    reviewer: selectOptions(uniqueValues(rows.map((row) => row.reviewer)).map((value) => [value, value])),
    owner: selectOptions(uniqueValues(rows.map((row) => row.owner)).map((value) => [value, value])),
    deployment: selectOptions(deployOptions),
  };
  const columns = [
    { key: "repo", label: "Repository", title: "The repository this scan reviewed." },
    { key: "findings", label: "Findings", title: "How many findings this report contains." },
    { key: "severity", label: "Severity", title: "Critical, high, medium, low, and informational." },
    { key: "blocking", label: "Blocking", title: "Findings whose pull status is block. This is the count that fails deployment." },
    { key: "deployment", label: "Deployment", title: "Failed means at least one finding blocks deployment. Passed means none do." },
    { key: "class", label: "Data class", title: "How sensitive the service is. Restricted can turn a high finding into a block." },
    { key: "reviewer", label: "Reviewer", title: "The role that last wrote this report." },
    { key: "owner", label: "Owner", title: "The team accountable for the service." },
    { key: "scanned", label: "Scanned", title: "When this report's latest scan finished, in UTC." },
  ];
  const header = columns.map((column) =>
    `<th data-sort="${column.key}" aria-sort="none"><button type="button" title="${escapeHtml(column.title)}">${escapeHtml(column.label)}</button></th>`).join("");
  const filterRow = columns.map((column) => {
    if (filters[column.key]) {
      return `<th><select data-filter="${column.key}" aria-label="Filter ${escapeHtml(column.label)}">${filters[column.key]}</select></th>`;
    }
    return `<th><input data-filter="${column.key}" aria-label="Filter ${escapeHtml(column.label)}" placeholder="Filter"></th>`;
  }).join("");
  const body = rows.map((row) => {
    const failedRow = row.check === "failure";
    const scanned = row.scanned ? `${row.scanned} UTC` : "";
    return `<tr class="report" data-repo="${escapeHtml(row.repoName)}" data-findings="${row.total}" data-findings-rank="${row.total}" data-severity="${escapeHtml(severityText(row.counts))}" data-severity-rank="${severityRank(row.counts)}" data-blocking="${row.blocking}" data-blocking-rank="${row.blocking}" data-deployment="${failedRow ? "failed" : "passed"}" data-deployment-rank="${failedRow ? 0 : 1}" data-class="${escapeHtml(row.dataClass)}" data-reviewer="${escapeHtml(row.reviewer)}" data-owner="${escapeHtml(row.owner)}" data-scanned="${escapeHtml(scanned)}">
      <td><a href="${escapeHtml(row.reportFile)}">${escapeHtml(row.repoName)}</a></td>
      <td class="num">${row.total}</td>
      <td>${severityChips(row.counts)}</td>
      <td class="num">${row.blocking}</td>
      <td><span class="chip check check-${escapeHtml(row.check)}">${escapeHtml(deploymentLabel(row.check))}</span></td>
      <td>${escapeHtml(row.dataClass)}</td>
      <td>${escapeHtml(row.reviewer)}</td>
      <td>${escapeHtml(row.owner)}</td>
      <td>${escapeHtml(scanned)}</td>
    </tr>`;
  }).join("");
  const empty = body || `<tr class="empty"><td colspan="${columns.length}">No reports yet.</td></tr>`;
  const failedClass = failed ? "stat-value stat-failed" : "stat-value";
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Findings dashboard</title>
  <style>
${reportThemeCss}
    .stats { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 0.9rem; }
    .stat-value { margin: 0; font-size: 1.55rem; font-weight: 650; font-variant-numeric: tabular-nums; letter-spacing: -0.02em; }
    .stat-label { margin: 0.15rem 0 0; color: var(--muted); font-size: 0.82rem; }
    .stat-failed { color: var(--critical); }
    .reports { margin-top: 0.9rem; }
    .reports table { min-width: 72rem; }
    tr.report:hover td { background: var(--soft); }
    tr.report[hidden] { display: none; }
    .num { font-variant-numeric: tabular-nums; }
    .sev { display: inline-flex; gap: 0.28rem; white-space: nowrap; }
    .chip.zero { opacity: 0.4; }
    .chart-wide { grid-column: 1 / -1; }
    .charts .bars li { grid-template-columns: 7.6rem 1fr 3rem; }
    .charts .wide-labels .bars li { grid-template-columns: 12.5rem 1fr 3rem; }
    .charts .stacks li { grid-template-columns: minmax(10rem, 20rem) 1fr 3rem; }
    .stacks .bar-label { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .stacks .bar-track { display: flex; }
    .stack { display: flex; flex: 1 1 auto; height: 100%; min-width: 0; }
    .stack .bar-fill { border-radius: 0; height: 100%; }
    .legend { display: flex; flex-wrap: wrap; gap: 0.7rem 1rem; margin: 0.75rem 0 0; color: var(--muted); font-size: 0.8rem; align-items: center; }
    .swatch { display: inline-block; width: 0.65rem; height: 0.65rem; border-radius: 2px; margin-right: 0.35rem; vertical-align: -0.08rem; }
    .fill-accent { background: var(--accent); }
    @media (max-width: 860px) {
      .stats { grid-template-columns: 1fr 1fr; }
    }
    @media (max-width: 560px) {
      .stats { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class="page">
    <h1>Findings dashboard</h1>
    <p class="note">Latest scan for each repository that has a current report. Archived copies are not listed.</p>
    <section class="stats" aria-label="Summary">
      ${statCard(rows.length, "Reports")}
      ${statCard(failed, "Failed deployments", failedClass)}
      ${statCard(findings, "Findings")}
      ${statCard(blocking, "Blocking findings")}
    </section>
    <section class="reports card">
      <h2>Reports <span id="report-count" class="count"></span></h2>
      <p class="tools"><button type="button" id="clear-filters">Clear filters</button></p>
      <div class="wrap">
        <table id="reports">
          <thead>
            <tr>${header}</tr>
            <tr class="filters">${filterRow}</tr>
          </thead>
          <tbody>
            ${empty}
          </tbody>
        </table>
      </div>
    </section>
    <section class="charts">
      ${barChart("Risk", "Findings in each risk classification across the reports listed above.", riskRows)}
      ${barChart("Deployment", "Reports that failed or passed deployment.", deployRows)}
      ${stackedChart(rows)}
      ${barChart("Class", "Findings in each vulnerability class.", classRows, "wide-labels")}
      ${barChart("Pull status", "Findings that block, comment, or were cleared.", gateRows)}
    </section>
  </div>
  <script>
    (function () {
      const table = document.getElementById("reports");
      if (!table) return;
      const headers = [...table.querySelectorAll("thead th[data-sort]")];
      const count = document.getElementById("report-count");
      const clear = document.getElementById("clear-filters");
      let sortKey = "";
      let sortDir = 1;
      function groups() {
        return [...table.querySelectorAll("tr.report")];
      }
      function compare(left, right) {
        if (!sortKey) {
          const deploy = Number(left.getAttribute("data-deployment-rank")) - Number(right.getAttribute("data-deployment-rank"));
          if (deploy) return deploy;
          const block = Number(right.getAttribute("data-blocking-rank")) - Number(left.getAttribute("data-blocking-rank"));
          if (block) return block;
          return (left.getAttribute("data-repo") || "").localeCompare(right.getAttribute("data-repo") || "", undefined, { numeric: true, sensitivity: "base" });
        }
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
        const listed = groups().sort(compare);
        let shown = 0;
        const body = table.querySelector("tbody");
        for (const row of listed) {
          body.appendChild(row);
          const hide = Object.entries(filters).some(([key, query]) => {
            if (!query) return false;
            return !(row.getAttribute("data-" + key) || "").toLowerCase().includes(query);
          });
          row.hidden = hide;
          if (!hide) shown += 1;
        }
        if (count) {
          const total = listed.length;
          const noun = total === 1 ? "report" : "reports";
          count.textContent = shown === total ? total + " " + noun : "Showing " + shown + " of " + total;
        }
        headers.forEach((headerCell) => {
          const key = headerCell.getAttribute("data-sort");
          headerCell.setAttribute("aria-sort", sortKey && key === sortKey ? (sortDir === 1 ? "ascending" : "descending") : "none");
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
</html>
`;
}

export function writeDashboard(db) {
  fs.mkdirSync(outDir, { recursive: true });
  const file = dashboardPath();
  fs.writeFileSync(file, renderDashboard(loadRows(db)));
  return file;
}
