import { helpText } from "./lib/help.mjs";
import { adjudicate } from "./lib/pipeline.mjs";

function parseArgs(argv) {
  const args = { as: "developer", finding: "", label: "false_positive", help: false };
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === "--help") args.help = true;
    else if (argv[i] === "--as") args.as = argv[++i];
    else if (argv[i] === "--finding") args.finding = argv[++i];
    else if (argv[i] === "--label") args.label = argv[++i];
  }
  return args;
}

const args = parseArgs(process.argv.slice(2));
if (args.help) {
  process.stdout.write(helpText());
  process.exit(0);
}
if (!args.finding) {
  process.stderr.write("Usage: node adjudicate.mjs --finding <id> --label <false_positive|true_positive|accepted_risk> --as <developer|appsec>\n");
  process.exit(1);
}

try {
  const result = adjudicate({ findingId: args.finding, label: args.label, role: args.as });
  process.stdout.write(`${JSON.stringify(result)}\n`);
} catch (error) {
  process.stderr.write(`${error.message}\n`);
  process.exit(1);
}
