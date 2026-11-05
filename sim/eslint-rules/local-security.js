const SQL_SHAPE = /\bselect\b[\s\S]{0,400}\bfrom\b|\border\s+by\b|\binsert\s+into\b|\bupdate\b[\s\S]{0,80}\bset\b|\bdelete\s+from\b/i;
const MONGO_OP = /\$(where|gt|gte|lt|lte|ne|in|nin|regex|eq|expr)\b/;
const LDAP_FILTER = /\([A-Za-z][\w-]*\s*[=<>~]/;
const MARKUP = /<\/?[a-z][\w:-]*\b/i;
const WEAK_HASH = new Set(["md5", "sha1", "md4"]);
const WEAK_TLS = new Set([
  "TLSv1", "TLSv1.0", "TLSv1.1", "SSLv2", "SSLv3", "SSLv23",
  "TLSv1_method", "TLSv1_1_method", "SSLv2_method", "SSLv3_method", "SSLv23_method",
]);
const COOKIE_FLAGS = new Set(["httpOnly", "secure", "sameSite"]);
const PRIVILEGED = {
  role: "role",
  isAdmin: "is-admin",
  tenantId: "tenant-id",
  ownerId: "owner-id",
  price: "price",
  quantity: "quantity",
  status: "status",
};
const SECRET_NAMES = new Set(["password", "secret", "token", "authorization"]);
const FILTER_ESCAPES = new Set(["escapeFilter", "ldapEscape", "escapeLDAP"]);
const CONTROL_SANITIZERS = new Set(["stripControl", "stripCrlf", "sanitizeHeader", "escapeCsv"]);
const TEMPLATE_ENGINES = new Set(["ejs", "pug", "handlebars", "nunjucks", "hbs", "eta", "dot", "vm"]);
const HTTP_CLIENTS = new Set(["http", "https", "axios", "got", "request"]);
const LOG_METHODS = new Set(["log", "info", "warn", "error", "debug", "trace"]);
const SKIP_WALK = new Set(["parent", "loc", "range", "start", "end", "tokens"]);

function isSqlText(value) {
  return typeof value === "string" && SQL_SHAPE.test(value);
}

function isSqlLiteral(node) {
  return Boolean(node && node.type === "Literal" && isSqlText(node.value));
}

function chainHasSql(node) {
  if (!node) return false;
  if (isSqlLiteral(node)) return true;
  if (node.type === "TemplateLiteral") return templateHasSql(node);
  if (node.type === "BinaryExpression" && node.operator === "+") {
    return chainHasSql(node.left) || chainHasSql(node.right);
  }
  return false;
}

function templateHasSql(node) {
  if (!node || node.type !== "TemplateLiteral" || node.expressions.length === 0) return false;
  const text = node.quasis.map((part) => part.value.cooked || part.value.raw || "").join(" ");
  return isSqlText(text);
}

function calleeName(node) {
  if (!node) return "";
  if (node.type === "Identifier") return node.name;
  if (node.type === "MemberExpression" && !node.computed && node.property.type === "Identifier") {
    return node.property.name;
  }
  return "";
}

function propertyName(node) {
  if (!node || node.type !== "MemberExpression") return "";
  if (!node.computed && node.property.type === "Identifier") return node.property.name;
  if (node.computed && node.property.type === "Literal") return String(node.property.value);
  return "";
}

function keyName(property) {
  if (!property || property.type !== "Property" || property.computed) return "";
  if (property.key.type === "Identifier") return property.key.name;
  if (property.key.type === "Literal") return String(property.key.value);
  return "";
}

function isNonLiteral(node) {
  if (!node) return false;
  if (node.type === "Literal") return false;
  if (node.type === "TemplateLiteral" && node.expressions.length === 0) return false;
  return true;
}

function walk(node, visit, seen = new Set()) {
  if (!node || typeof node.type !== "string" || seen.has(node)) return;
  seen.add(node);
  visit(node);
  for (const [key, value] of Object.entries(node)) {
    if (SKIP_WALK.has(key)) continue;
    if (Array.isArray(value)) value.forEach((item) => walk(item, visit, seen));
    else if (value && typeof value === "object") walk(value, visit, seen);
  }
}

function rootedInRequest(node) {
  let current = node;
  while (current) {
    if (current.type === "Identifier" && (current.name === "req" || current.name === "request")) return true;
    if (current.type === "MemberExpression") current = current.object;
    else if (current.type === "CallExpression") current = current.callee;
    else break;
  }
  return false;
}

function fromBody(node) {
  let current = node;
  while (current && current.type === "MemberExpression") {
    if (propertyName(current) === "body") {
      const object = current.object;
      return object.type === "Identifier" && (object.name === "req" || object.name === "request");
    }
    current = current.object;
  }
  return false;
}

function mentionsName(node, names) {
  if (!node) return false;
  if (node.type === "Identifier") return names.has(node.name);
  if (node.type === "MemberExpression") {
    const name = propertyName(node);
    if (names.has(name)) return true;
    return mentionsName(node.object, names) || (node.computed && mentionsName(node.property, names));
  }
  return false;
}

function comparisonMentionsToken(node) {
  let current = node.parent;
  for (let depth = 0; depth < 4 && current; depth += 1) {
    if (current.type === "BinaryExpression" && ["==", "===", "!=", "!=="].includes(current.operator)) {
      if (mentionsName(current.left, new Set(["token"])) || mentionsName(current.right, new Set(["token"]))) return true;
    }
    current = current.parent;
  }
  return false;
}

function enclosingFunction(node) {
  let current = node && node.parent;
  while (current) {
    if (current.type === "FunctionDeclaration" || current.type === "FunctionExpression" || current.type === "ArrowFunctionExpression") {
      return current;
    }
    current = current.parent;
  }
  return null;
}

function insideTry(node) {
  let current = node && node.parent;
  while (current) {
    if (current.type === "TryStatement") return true;
    current = current.parent;
  }
  return false;
}

function requestPart(node, parts, field) {
  if (!node || node.type !== "MemberExpression" || propertyName(node) !== field) return false;
  const parent = node.object;
  if (!parent || parent.type !== "MemberExpression" || !parts.includes(propertyName(parent))) return false;
  const root = parent.object;
  return Boolean(root && root.type === "Identifier" && (root.name === "req" || root.name === "request"));
}

function requestIdentity(node) {
  return requestPart(node, ["body", "query"], "login") || requestPart(node, ["body", "query"], "username");
}

function requestId(node) {
  return requestPart(node, ["body", "query", "params"], "id");
}

function usesIdentifier(node, name) {
  let found = false;
  walk(node, (current) => {
    if (current.type === "Identifier" && current.name === name) found = true;
  });
  return found;
}

function isResponseJson(node) {
  if (!node || node.type !== "CallExpression" || node.callee.type !== "MemberExpression") return false;
  const name = calleeName(node.callee);
  if (name !== "json" && name !== "send") return false;
  let object = node.callee.object;
  if (object.type === "CallExpression" && object.callee.type === "MemberExpression") object = object.callee.object;
  return object.type === "Identifier" && (object.name === "res" || object.name === "response");
}

function isModelQuery(node) {
  if (!node.callee || node.callee.type !== "MemberExpression") return false;
  const object = node.callee.object;
  if (object.type === "MemberExpression") return true;
  return object.type === "Identifier" && /^[A-Z]/.test(object.name);
}

function objectUsesRequestId(object) {
  if (!object || object.type !== "ObjectExpression") return false;
  return object.properties.some((property) => {
    if (property.type !== "Property") return false;
    const key = keyName(property);
    if (key === "id" && requestId(property.value)) return true;
    if (key === "where") return objectUsesRequestId(property.value);
    return false;
  });
}

function loadedRecord(call) {
  const parent = call.parent;
  if (parent && parent.type === "MemberExpression" && parent.object === call && propertyName(parent) === "then") {
    const thenCall = parent.parent;
    const callback = thenCall && thenCall.type === "CallExpression" ? thenCall.arguments[0] : null;
    if (callback && (callback.type === "FunctionExpression" || callback.type === "ArrowFunctionExpression")) {
      const param = callback.params[0];
      if (param && param.type === "Identifier") return { name: param.name, scope: callback };
    }
  }
  let expr = call;
  if (expr.parent && expr.parent.type === "AwaitExpression") expr = expr.parent;
  if (expr.parent && expr.parent.type === "VariableDeclarator" && expr.parent.id.type === "Identifier") {
    return { name: expr.parent.id.name, scope: enclosingFunction(call) };
  }
  return null;
}

function writesRecord(scope, name) {
  if (!scope || !name) return false;
  let found = false;
  walk(scope, (current) => {
    if (current.type === "CallExpression" && calleeName(current.callee) === "save") {
      const object = current.callee.type === "MemberExpression" ? current.callee.object : null;
      if (object && object.type === "Identifier" && object.name === name) found = true;
    }
    if (current.type === "AssignmentExpression" && current.left.type === "MemberExpression" && current.left.object.type === "Identifier" && current.left.object.name === name) {
      found = true;
    }
  });
  return found;
}

function resultIsSent(call) {
  const loaded = loadedRecord(call);
  if (!loaded) return false;
  let found = false;
  walk(loaded.scope, (current) => {
    if (current.type === "CallExpression" && isResponseJson(current) && current.arguments.some((arg) => usesIdentifier(arg, loaded.name))) {
      found = true;
    }
  });
  return found;
}

function routePath(node) {
  const arg = node.arguments[0];
  if (arg && arg.type === "Literal" && typeof arg.value === "string") return arg.value;
  if (arg && arg.type === "TemplateLiteral" && arg.expressions.length === 0) {
    return arg.quasis.map((part) => part.value.cooked || "").join("");
  }
  return "";
}

function handlerChecksAdmin(arg) {
  if (!arg) return false;
  if (arg.type === "Identifier" && /admin|role|authoriz/i.test(arg.name)) return true;
  if (arg.type === "MemberExpression" && /admin|role|authoriz/i.test(propertyName(arg))) return true;
  if (arg.type === "FunctionExpression" || arg.type === "ArrowFunctionExpression") {
    let found = false;
    walk(arg.body, (current) => {
      if (current.type === "Identifier" && (current.name === "role" || current.name === "isAdmin")) found = true;
      if (current.type === "MemberExpression" && (propertyName(current) === "role" || propertyName(current) === "isAdmin")) found = true;
    });
    return found;
  }
  return false;
}

function md5OfLogin(node) {
  const name = calleeName(node.callee);
  if (name === "md5") return node.arguments.some(requestIdentity);
  if (name !== "update" || node.callee.type !== "MemberExpression") return false;
  const target = node.callee.object;
  if (!target || target.type !== "CallExpression" || calleeName(target.callee) !== "createHash") return false;
  const algo = target.arguments[0];
  if (!algo || algo.type !== "Literal" || String(algo.value).toLowerCase() !== "md5") return false;
  return node.arguments.some(requestIdentity);
}

function hasNoentTrue(node) {
  if (!node || node.type !== "ObjectExpression") return false;
  return node.properties.some((property) => keyName(property) === "noent"
    && property.value.type === "Literal"
    && property.value.value === true);
}

function objectName(callee) {
  if (!callee || callee.type !== "MemberExpression" || callee.object.type !== "Identifier") return "";
  return callee.object.name;
}

function report(context, node, messageId, pattern) {
  context.report({ node, messageId, data: { pattern } });
}

function literalText(node) {
  let text = "";
  walk(node, (current) => {
    if (current.type === "Literal" && typeof current.value === "string") text += ` ${current.value}`;
    if (current.type === "TemplateElement") text += ` ${current.value.cooked || current.value.raw || ""}`;
  });
  return text;
}

function usesHostHeader(node) {
  let found = false;
  walk(node, (current) => {
    if (current.type === "MemberExpression") {
      const name = propertyName(current);
      if ((name === "host" || name === "hostname") && rootedInRequest(current)) found = true;
    }
    if (current.type === "CallExpression" && calleeName(current.callee) === "get") {
      const arg = current.arguments[0];
      const host = arg && arg.type === "Literal" && String(arg.value).toLowerCase() === "host";
      if (host && current.callee.type === "MemberExpression" && rootedInRequest(current.callee.object)) found = true;
    }
  });
  return found;
}

function callIsSanitizer(node, names) {
  return Boolean(node && node.type === "CallExpression" && names.has(calleeName(node.callee)));
}

function interpolatedUnsafe(node, sanitizers) {
  const leaves = [];
  function visit(current) {
    if (!current) return;
    if (callIsSanitizer(current, sanitizers)) return;
    if (current.type === "Identifier") leaves.push(current);
    if (current.type === "MemberExpression") visit(current.object);
    if (current.type === "BinaryExpression" && current.operator === "+") {
      visit(current.left);
      visit(current.right);
    }
    if (current.type === "TemplateLiteral") current.expressions.forEach(visit);
  }
  visit(node);
  return leaves.length > 0;
}

const marked = (text) => `${text} [pattern:{{pattern}}]`;

const stringConcatQuery = {
  meta: {
    type: "problem",
    messages: { concat: marked("SQL built by concatenating a query string.") },
    schema: [],
  },
  create(context) {
    return {
      BinaryExpression(node) {
        if (node.operator !== "+") return;
        if (node.parent && node.parent.type === "BinaryExpression" && node.parent.operator === "+") return;
        if (chainHasSql(node)) report(context, node, "concat", "sql");
      },
      TemplateLiteral(node) {
        if (templateHasSql(node)) report(context, node, "concat", "sql");
      },
    };
  },
};

const sqlLiteral = {
  meta: {
    type: "suggestion",
    messages: { literal: marked("SQL query literal.") },
    schema: [],
  },
  create(context) {
    return {
      Literal(node) {
        if (isSqlLiteral(node)) report(context, node, "literal", "sql");
      },
    };
  },
};

const dangerousHtml = {
  meta: {
    type: "problem",
    messages: { html: marked("Unsanitized HTML sink.") },
    schema: [],
  },
  create(context) {
    function markupBuilt(node) {
      return Boolean(node) && MARKUP.test(literalText(node)) && interpolatedUnsafe(node, new Set());
    }
    return {
      JSXAttribute(node) {
        if (node.name && node.name.type === "JSXIdentifier" && node.name.name === "dangerouslySetInnerHTML") {
          report(context, node, "html", "html");
        }
      },
      AssignmentExpression(node) {
        if (propertyName(node.left) !== "innerHTML") return;
        if (!isNonLiteral(node.right)) return;
        report(context, node, "html", "html");
      },
      CallExpression(node) {
        const name = calleeName(node.callee);
        if (!["send", "end", "write"].includes(name)) return;
        if (!node.arguments.some(markupBuilt)) return;
        report(context, node, "html", "html");
      },
    };
  },
};

const memberEval = {
  meta: {
    type: "problem",
    messages: { eval: marked("Dynamic eval of a non-literal value.") },
    schema: [],
  },
  create(context) {
    function check(node) {
      const name = calleeName(node.callee);
      const member = node.callee.type === "MemberExpression" && name === "eval";
      const functionCtor = name === "Function";
      if (!member && !functionCtor) return;
      if (!isNonLiteral(node.arguments[0])) return;
      report(context, node, "eval", "eval");
    }
    return { CallExpression: check, NewExpression: check };
  },
};

const unserializeCall = {
  meta: {
    type: "problem",
    messages: { unserialize: marked("Unserialize call.") },
    schema: [],
  },
  create(context) {
    return {
      CallExpression(node) {
        const name = calleeName(node.callee);
        if (name === "unserialize") report(context, node, "unserialize", "unserialize");
        if (name === "unsafeLoad") report(context, node, "unserialize", "yaml");
        if (name === "load" && /yaml/i.test(objectName(node.callee))) {
          report(context, node, "unserialize", "yaml");
        }
      },
    };
  },
};

const requestRedirect = {
  meta: {
    type: "problem",
    messages: { redirect: marked("Redirect target comes from the request.") },
    schema: [],
  },
  create(context) {
    return {
      CallExpression(node) {
        if (calleeName(node.callee) !== "redirect") return;
        if (node.arguments.some(usesHostHeader)) report(context, node, "redirect", "host");
        else if (node.arguments.some(rootedInRequest)) report(context, node, "redirect", "redirect");
      },
    };
  },
};

const xmlEntities = {
  meta: {
    type: "problem",
    messages: { xml: marked("XML parser has entity substitution enabled.") },
    schema: [],
  },
  create(context) {
    return {
      CallExpression(node) {
        const name = calleeName(node.callee);
        if (name !== "parseXml" && name !== "parseXmlString") return;
        if (!node.arguments.some(hasNoentTrue)) return;
        report(context, node, "xml", "xml");
      },
    };
  },
};

const md5Token = {
  meta: {
    type: "problem",
    messages: { crypto: marked("Weak cryptography used for a security value.") },
    schema: [],
  },
  create(context) {
    return {
      CallExpression(node) {
        const name = calleeName(node.callee);
        if (name === "md5" && comparisonMentionsToken(node)) report(context, node, "crypto", "weak-hash");
        if (name === "createHash" || name === "createHmac") {
          const algo = node.arguments[0];
          if (algo && algo.type === "Literal" && WEAK_HASH.has(String(algo.value).toLowerCase())) {
            report(context, node, "crypto", "weak-hash");
          }
        }
        if (name === "createCipheriv") {
          const iv = node.arguments[2];
          if (iv && iv.type === "Literal") report(context, node, "crypto", "static-iv");
        }
        if (name === "random" && objectName(node.callee) === "Math") {
          const id = node.parent && node.parent.type === "VariableDeclarator" ? node.parent.id : null;
          const declared = id && id.type === "Identifier" ? id.name : "";
          if (SECRET_NAMES.has(declared)) report(context, node, "crypto", "insecure-random");
        }
      },
      BinaryExpression(node) {
        if (!["==", "==="].includes(node.operator)) return;
        const secret = mentionsName(node.left, SECRET_NAMES) || mentionsName(node.right, SECRET_NAMES);
        if (!secret) return;
        report(context, node, "crypto", "unsafe-compare");
      },
    };
  },
};

const nosqlOperator = {
  meta: {
    type: "problem",
    messages: { nosql: marked("Query object built with a Mongo operator from the request.") },
    schema: [],
  },
  create(context) {
    function textHits(node) {
      return MONGO_OP.test(literalText(node)) && interpolatedUnsafe(node, new Set());
    }
    return {
      Property(node) {
        if (!MONGO_OP.test(keyName(node))) return;
        if (!rootedInRequest(node.value)) return;
        report(context, node, "nosql", "nosql");
      },
      BinaryExpression(node) {
        if (node.operator !== "+") return;
        if (node.parent && node.parent.type === "BinaryExpression" && node.parent.operator === "+") return;
        if (textHits(node)) report(context, node, "nosql", "nosql");
      },
      TemplateLiteral(node) {
        if (node.expressions.length === 0) return;
        if (textHits(node)) report(context, node, "nosql", "nosql");
      },
    };
  },
};

const ldapFilter = {
  meta: {
    type: "problem",
    messages: { ldap: marked("LDAP filter built by concatenation.") },
    schema: [],
  },
  create(context) {
    function hits(node) {
      return LDAP_FILTER.test(literalText(node)) && interpolatedUnsafe(node, FILTER_ESCAPES);
    }
    return {
      BinaryExpression(node) {
        if (node.operator !== "+") return;
        if (node.parent && node.parent.type === "BinaryExpression" && node.parent.operator === "+") return;
        if (hits(node)) report(context, node, "ldap", "ldap");
      },
      TemplateLiteral(node) {
        if (node.expressions.length && hits(node)) report(context, node, "ldap", "ldap");
      },
    };
  },
};

const urlFetch = {
  meta: {
    type: "problem",
    messages: { fetch: marked("Outbound request URL is not a literal.") },
    schema: [],
  },
  create(context) {
    return {
      CallExpression(node) {
        const name = calleeName(node.callee);
        const object = objectName(node.callee);
        const direct = node.callee.type === "Identifier" && (name === "fetch" || name === "axios");
        const method = ["get", "request", "post"].includes(name) && HTTP_CLIENTS.has(object);
        if (!direct && !method) return;
        if (name === "axios" && node.callee.type === "Identifier") {
          const options = node.arguments[0];
          const url = options && options.type === "ObjectExpression"
            ? options.properties.find((property) => keyName(property) === "url")
            : null;
          if (url && isNonLiteral(url.value)) report(context, node, "fetch", "fetch");
          return;
        }
        if (isNonLiteral(node.arguments[0])) report(context, node, "fetch", "fetch");
      },
    };
  },
};

const controlChar = {
  meta: {
    type: "problem",
    messages: { control: marked("Request data written into a header, log, message, or CSV row.") },
    schema: [],
  },
  create(context) {
    function unsafeRequest(node) {
      if (!node || callIsSanitizer(node, CONTROL_SANITIZERS)) return false;
      if (fromBody(node) || mentionsName(node, SECRET_NAMES)) return false;
      let found = false;
      walk(node, (current) => {
        if (rootedInRequest(current)) found = true;
      });
      return found;
    }
    return {
      CallExpression(node) {
        const name = calleeName(node.callee);
        if (["setHeader", "header"].includes(name)) {
          const value = node.arguments[1];
          if (value && unsafeRequest(value)) report(context, node, "control", "header");
        }
        if (name === "sendMail" && node.arguments.some(unsafeRequest)) report(context, node, "control", "mail");
        if (["writeCsv", "csvRow"].includes(name) && node.arguments.some(unsafeRequest)) {
          report(context, node, "control", "csv");
        }
        if (LOG_METHODS.has(name) && node.arguments.some(unsafeRequest)) report(context, node, "control", "log");
      },
    };
  },
};

const cookieFlags = {
  meta: {
    type: "problem",
    messages: { cookie: marked("Cookie is set without httpOnly, secure, or sameSite.") },
    schema: [],
  },
  create(context) {
    function hasFlag(node) {
      return node.properties.some((property) => COOKIE_FLAGS.has(keyName(property)));
    }
    return {
      CallExpression(node) {
        if (calleeName(node.callee) !== "cookie") return;
        const options = node.arguments[2];
        if (options && options.type !== "ObjectExpression") return;
        if (options && hasFlag(options)) return;
        report(context, node, "cookie", "cookie");
      },
    };
  },
};

const jwtVerify = {
  meta: {
    type: "problem",
    messages: { jwt: marked("JWT verification does not pin a signature algorithm.") },
    schema: [],
  },
  create(context) {
    function jwtCall(node, name) {
      if (calleeName(node.callee) !== name) return false;
      return /^(jwt|jose)$/i.test(objectName(node.callee));
    }
    return {
      CallExpression(node) {
        if (jwtCall(node, "decode")) report(context, node, "jwt", "decode");
        if (!jwtCall(node, "verify")) return;
        const options = node.arguments[2];
        if (!options) {
          report(context, node, "jwt", "missing-algorithms");
          return;
        }
        if (options.type !== "ObjectExpression") return;
        const algorithms = options.properties.find((property) => keyName(property) === "algorithms");
        if (!algorithms) {
          report(context, node, "jwt", "missing-algorithms");
          return;
        }
        const values = algorithms.value.type === "ArrayExpression"
          ? algorithms.value.elements.filter((item) => item && item.type === "Literal").map((item) => String(item.value))
          : [];
        if (values.includes("none")) report(context, node, "jwt", "none");
      },
    };
  },
};

const tlsVerify = {
  meta: {
    type: "problem",
    messages: { tls: marked("TLS verification is disabled or negotiated down.") },
    schema: [],
  },
  create(context) {
    return {
      Property(node) {
        const key = keyName(node);
        if (key === "rejectUnauthorized" && node.value.type === "Literal" && node.value.value === false) {
          report(context, node, "tls", "tls");
        }
        if (key === "checkServerIdentity") report(context, node, "tls", "tls");
        if ((key === "minVersion" || key === "secureProtocol") && node.value.type === "Literal" && WEAK_TLS.has(String(node.value.value))) {
          report(context, node, "tls", "tls");
        }
      },
      AssignmentExpression(node) {
        if (propertyName(node.left) !== "NODE_TLS_REJECT_UNAUTHORIZED") return;
        const value = node.right.type === "Literal" ? String(node.right.value) : "";
        if (value === "0") report(context, node, "tls", "tls");
      },
    };
  },
};

const privilegedField = {
  meta: {
    type: "problem",
    messages: { field: marked("Privileged field is copied from the request body.") },
    schema: [],
  },
  create(context) {
    return {
      AssignmentExpression(node) {
        const pattern = PRIVILEGED[propertyName(node.left)];
        if (!pattern || !fromBody(node.right)) return;
        report(context, node, "field", pattern);
      },
      Property(node) {
        const pattern = PRIVILEGED[keyName(node)];
        if (!pattern || !fromBody(node.value)) return;
        report(context, node, "field", pattern);
      },
      CallExpression(node) {
        const name = calleeName(node.callee);
        if (!["assign", "merge", "extend"].includes(name)) return;
        if (!node.arguments.some((argument) => fromBody(argument) && propertyName(argument) === "body")) return;
        report(context, node, "field", "merge");
      },
    };
  },
};

const originTrust = {
  meta: {
    type: "problem",
    messages: { origin: marked("Caller-supplied origin is trusted.") },
    schema: [],
  },
  create(context) {
    return {
      ObjectExpression(node) {
        const credentials = node.properties.find((property) => keyName(property) === "credentials");
        const origin = node.properties.find((property) => keyName(property) === "origin");
        if (!credentials || !origin) return;
        if (credentials.value.type !== "Literal" || credentials.value.value !== true) return;
        const value = origin.value;
        if (value.type === "Literal" && (value.value === "*" || value.value === true)) {
          report(context, node, "origin", "wildcard");
        } else if (isNonLiteral(value)) report(context, node, "origin", "reflected");
      },
      CallExpression(node) {
        if (calleeName(node.callee) !== "postMessage") return;
        const target = node.arguments[1];
        if (!target || (target.type === "Literal" && target.value === "*") || isNonLiteral(target)) {
          report(context, node, "origin", "postmessage");
        }
      },
    };
  },
};

const browserSecret = {
  meta: {
    type: "problem",
    messages: { storage: marked("Secret stored in browser web storage.") },
    schema: [],
  },
  create(context) {
    return {
      CallExpression(node) {
        if (calleeName(node.callee) !== "setItem") return;
        if (!["localStorage", "sessionStorage"].includes(objectName(node.callee))) return;
        const source = context.sourceCode || context.getSourceCode();
        const text = node.arguments.map((argument) => source.getText(argument)).join(" ");
        if (!/token|password|secret|session|jwt/i.test(text)) return;
        report(context, node, "storage", "storage");
      },
    };
  },
};

const sensitiveLog = {
  meta: {
    type: "problem",
    messages: { log: marked("Password, token, or request body written to a log.") },
    schema: [],
  },
  create(context) {
    return {
      CallExpression(node) {
        if (!LOG_METHODS.has(calleeName(node.callee))) return;
        const hit = node.arguments.some((argument) => fromBody(argument) || mentionsName(argument, SECRET_NAMES));
        if (hit) report(context, node, "log", "log");
      },
    };
  },
};

const errorToClient = {
  meta: {
    type: "problem",
    messages: { error: marked("Error detail sent to the client.") },
    schema: [],
  },
  create(context) {
    function isDetail(node) {
      let found = false;
      walk(node, (current) => {
        if (current.type === "Identifier" && (current.name === "err" || current.name === "error")) found = true;
        if (current.type === "MemberExpression") {
          const prop = propertyName(current);
          if ((prop === "stack" || prop === "message")
            && current.object.type === "Identifier"
            && (current.object.name === "err" || current.object.name === "error")) found = true;
        }
      });
      return found;
    }
    return {
      CallExpression(node) {
        const name = calleeName(node.callee);
        if (!["send", "json", "end"].includes(name)) return;
        if (!node.arguments.some(isDetail)) return;
        report(context, node, "error", "stack");
      },
    };
  },
};

const templateRender = {
  meta: {
    type: "problem",
    messages: { template: marked("Template source is not a literal.") },
    schema: [],
  },
  create(context) {
    return {
      CallExpression(node) {
        const name = calleeName(node.callee);
        if (name !== "render" && name !== "compile") return;
        if (!TEMPLATE_ENGINES.has(objectName(node.callee))) return;
        if (!isNonLiteral(node.arguments[0])) return;
        report(context, node, "template", "template");
      },
      NewExpression(node) {
        if (calleeName(node.callee) !== "Script" || objectName(node.callee) !== "vm") return;
        if (!isNonLiteral(node.arguments[0])) return;
        report(context, node, "template", "template");
      },
    };
  },
};

const sessionSecret = {
  meta: {
    type: "problem",
    messages: { secret: marked("Session secret is a string literal.") },
    schema: [],
  },
  create(context) {
    return {
      CallExpression(node) {
        if (calleeName(node.callee) !== "session") return;
        const options = node.arguments.find((arg) => arg.type === "ObjectExpression");
        if (!options) return;
        const secret = options.properties.find((property) => keyName(property) === "secret");
        if (!secret || secret.value.type !== "Literal" || typeof secret.value.value !== "string") return;
        report(context, secret, "secret", "session");
      },
    };
  },
};

const resetToken = {
  meta: {
    type: "problem",
    messages: { reset: marked("Password reset token is a hash of the login.") },
    schema: [],
  },
  create(context) {
    return {
      CallExpression(node) {
        if (!md5OfLogin(node) || !comparisonMentionsToken(node)) return;
        report(context, node, "reset", "reset");
      },
    };
  },
};

const sensitiveResponse = {
  meta: {
    type: "problem",
    messages: { response: marked("Full record sent in a JSON response.") },
    schema: [],
  },
  create(context) {
    return {
      CallExpression(node) {
        const name = calleeName(node.callee);
        if (!["find", "findOne", "findAll"].includes(name) || !isModelQuery(node)) return;
        const options = node.arguments.find((arg) => arg.type === "ObjectExpression");
        if (options && options.properties.some((property) => keyName(property) === "attributes")) return;
        if (!resultIsSent(node)) return;
        report(context, node, "response", "response");
      },
    };
  },
};

const ormQueryLog = {
  meta: {
    type: "problem",
    messages: { log: marked("Database client logs queries.") },
    schema: [],
  },
  create(context) {
    return {
      NewExpression(node) {
        if (calleeName(node.callee) !== "Sequelize") return;
        const options = [...node.arguments].reverse().find((arg) => arg.type === "ObjectExpression");
        if (options) {
          const logging = options.properties.find((property) => keyName(property) === "logging");
          if (logging && logging.value.type === "Literal" && logging.value.value === false) return;
        }
        report(context, node, "log", "query-log");
      },
    };
  },
};

const adminRoute = {
  meta: {
    type: "problem",
    messages: { admin: marked("Admin route has no admin check in this file.") },
    schema: [],
  },
  create(context) {
    return {
      CallExpression(node) {
        if (node.callee.type !== "MemberExpression") return;
        if (!["get", "post", "put", "patch", "delete", "all"].includes(calleeName(node.callee))) return;
        if (!routePath(node).includes("/admin")) return;
        if (node.arguments.slice(1).some(handlerChecksAdmin)) return;
        report(context, node, "admin", "admin");
      },
    };
  },
};

const objectId = {
  meta: {
    type: "problem",
    messages: { id: marked("Record id taken from the request and saved.") },
    schema: [],
  },
  create(context) {
    return {
      CallExpression(node) {
        const name = calleeName(node.callee);
        const usesId = name === "findByPk"
          ? node.arguments.some(requestId)
          : node.arguments.some((arg) => objectUsesRequestId(arg));
        if (!usesId) return;
        if (name === "update" || name === "destroy") {
          report(context, node, "id", "object-id");
          return;
        }
        if (!["find", "findOne", "findByPk"].includes(name)) return;
        const loaded = loadedRecord(node);
        if (!loaded || !writesRecord(loaded.scope, loaded.name)) return;
        report(context, node, "id", "object-id");
      },
    };
  },
};

const uncaughtSink = {
  meta: {
    type: "problem",
    messages: { uncaught: marked("Uncaught error can reach the client.") },
    schema: [],
  },
  create(context) {
    return {
      CallExpression(node) {
        if (calleeName(node.callee) !== "eval") return;
        if (!isNonLiteral(node.arguments[0]) || insideTry(node)) return;
        report(context, node, "uncaught", "uncaught");
      },
    };
  },
};

const errorMiddleware = {
  meta: {
    type: "problem",
    messages: { middleware: marked("Express app has no error handler.") },
    schema: [],
  },
  create(context) {
    let expressCall = null;
    let handled = false;
    return {
      CallExpression(node) {
        if (!expressCall && calleeName(node.callee) === "express" && node.arguments.length === 0) expressCall = node;
        if (calleeName(node.callee) !== "use") return;
        if (node.arguments.some((arg) => (arg.type === "FunctionExpression" || arg.type === "ArrowFunctionExpression") && arg.params.length >= 4)) {
          handled = true;
        }
      },
      "Program:exit"() {
        if (expressCall && !handled) report(context, expressCall, "middleware", "middleware");
      },
    };
  },
};

const poweredBy = {
  meta: {
    type: "problem",
    messages: { header: marked("X-Powered-By header left on.") },
    schema: [],
  },
  create(context) {
    let expressCall = null;
    let disabled = false;
    return {
      CallExpression(node) {
        if (!expressCall && calleeName(node.callee) === "express" && node.arguments.length === 0) expressCall = node;
        const name = calleeName(node.callee);
        if (name === "disable") {
          const arg = node.arguments[0];
          if (arg && arg.type === "Literal" && arg.value === "x-powered-by") disabled = true;
        }
        if (name === "set") {
          const key = node.arguments[0];
          const value = node.arguments[1];
          if (key && key.type === "Literal" && key.value === "x-powered-by" && value && value.type === "Literal" && value.value === false) {
            disabled = true;
          }
        }
      },
      "Program:exit"() {
        if (expressCall && !disabled) report(context, expressCall, "header", "powered-by");
      },
    };
  },
};

const authLog = {
  meta: {
    type: "problem",
    messages: { auth: marked("Failed sign-in is not logged.") },
    schema: [],
  },
  create(context) {
    return {
      CallExpression(node) {
        if (calleeName(node.callee) !== "done") return;
        const first = node.arguments[0];
        const second = node.arguments[1];
        if (!first || first.type !== "Literal" || first.value !== null) return;
        if (!second || second.type !== "Literal" || second.value !== false) return;
        const fn = enclosingFunction(node);
        if (!fn) return;
        let logged = false;
        walk(fn.body, (current) => {
          if (current.type === "CallExpression" && LOG_METHODS.has(calleeName(current.callee))) logged = true;
        });
        if (logged) return;
        report(context, node, "auth", "auth");
      },
    };
  },
};

const csrfRoute = {
  meta: {
    type: "problem",
    messages: { csrf: marked("State-changing route has no CSRF check.") },
    schema: [],
  },
  create(context) {
    const source = context.sourceCode || context.getSourceCode();
    const protectedFile = /csurf|csrf/i.test(source.getText());
    return {
      CallExpression(node) {
        if (protectedFile || node.callee.type !== "MemberExpression") return;
        if (!["post", "put", "patch", "delete"].includes(calleeName(node.callee))) return;
        if (!routePath(node)) return;
        report(context, node, "csrf", "csrf");
      },
    };
  },
};

export default {
  rules: {
    "string-concat-query": stringConcatQuery,
    "sql-literal": sqlLiteral,
    "dangerous-html": dangerousHtml,
    "member-eval": memberEval,
    unserialize: unserializeCall,
    "request-redirect": requestRedirect,
    "xml-entities": xmlEntities,
    "md5-token": md5Token,
    "nosql-operator": nosqlOperator,
    "ldap-filter": ldapFilter,
    "url-fetch": urlFetch,
    "control-char": controlChar,
    "cookie-flags": cookieFlags,
    "jwt-verify": jwtVerify,
    "tls-verify": tlsVerify,
    "privileged-field": privilegedField,
    "origin-trust": originTrust,
    "browser-secret": browserSecret,
    "sensitive-log": sensitiveLog,
    "error-to-client": errorToClient,
    "template-render": templateRender,
    "session-secret": sessionSecret,
    "reset-token": resetToken,
    "sensitive-response": sensitiveResponse,
    "orm-query-log": ormQueryLog,
    "admin-route": adminRoute,
    "object-id": objectId,
    "uncaught-sink": uncaughtSink,
    "error-middleware": errorMiddleware,
    "powered-by": poweredBy,
    "auth-log": authLog,
    csrf: csrfRoute,
  },
};
