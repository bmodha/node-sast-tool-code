import { helpText } from "./lib/help.mjs";
import { waive } from "./lib/pipeline.mjs";

function parseArgs(argv) {
  const args = { as: "developer", fingerprint: "", reason: "", hours: "24", help: false };
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === "--help") args.help = true;
    else if (argv[i] === "--as") args.as = argv[++i];
    else if (argv[i] === "--fingerprint") args.fingerprint = argv[++i];
    else if (argv[i] === "--reason") args.reason = argv[++i];
    else if (argv[i] === "--hours") args.hours = argv[++i];
  }
  return args;
}

const args = parseArgs(process.argv.slice(2));
if (args.help) {
  process.stdout.write(helpText());
  process.exit(0);
}
if (!args.fingerprint || !args.reason) {
  process.stderr.write("Usage: node waive.mjs --fingerprint <id> --reason <text> --hours <n> --as appsec\n");
  process.exit(1);
}

try {
  const result = waive({ fingerprint: args.fingerprint, reason: args.reason, hours: args.hours, role: args.as });
  process.stdout.write(`${JSON.stringify(result)}\n`);
} catch (error) {
  process.stderr.write(`${error.message}\n`);
  process.exit(1);
}
