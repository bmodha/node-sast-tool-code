import { helpText } from "./lib/help.mjs";
import { promoteSignature } from "./lib/pipeline.mjs";

function parseArgs(argv) {
  const args = { as: "developer", codeUnit: "", help: false };
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === "--help") args.help = true;
    else if (argv[i] === "--as") args.as = argv[++i];
    else if (argv[i] === "--code-unit") args.codeUnit = argv[++i];
  }
  return args;
}

const args = parseArgs(process.argv.slice(2));
if (args.help) {
  process.stdout.write(helpText());
  process.exit(0);
}
if (!args.codeUnit) {
  process.stderr.write("Usage: node promote-signature.mjs --code-unit <id> --as appsec\n");
  process.exit(1);
}

try {
  const result = promoteSignature({ codeUnitId: args.codeUnit, role: args.as });
  process.stdout.write(`${JSON.stringify(result)}\n`);
} catch (error) {
  process.stderr.write(`${error.message}\n`);
  process.exit(1);
}
