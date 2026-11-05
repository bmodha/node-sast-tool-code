function queryTemplate(orderId, sort) {
  const byId = `SELECT * FROM orders WHERE id = ${orderId}`;
  const ordered = "ORDER BY " + sort;
  return [byId, ordered];
}

function queryNosql(users, req) {
  return users.find({ "$where": req.body.filter });
}

function queryLdap(req) {
  const filter = "(&(uid=" + req.query.user + "))";
  return search(filter);
}

function fetchUrl(http, req) {
  return http.get("https://" + req.headers.host + "/internal");
}

function writeHeader(res, req, mailer, csv) {
  res.setHeader("X-File", req.query.name);
  console.log(req.query.name);
  mailer.sendMail({ subject: req.query.name });
  csv.writeCsv(req.query.row);
}

function setSessionCookie(res, id) {
  res.cookie("session", id);
}

function acceptJwt(jwt, token, secret) {
  jwt.decode(token);
  jwt.verify(token, secret);
  return jwt.verify(token, secret, { algorithms: ["none"] });
}

function trustTls(https) {
  return https.get("https://example.com/orders", { rejectUnauthorized: false });
}

function copyRole(user, req) {
  user.role = req.body.role;
}

function openCors(cors, frame, payload) {
  frame.postMessage(payload, "*");
  return cors({ origin: "*", credentials: true });
}

function storeToken(token) {
  localStorage.setItem("token", token);
}

function logPassword(password) {
  console.log(password);
}

function sendError(res, err) {
  res.send(err.stack);
}

function renderTemplate(ejs, req) {
  return ejs.render(req.body.template);
}

function loadYaml(yaml, payload) {
  return yaml.load(payload);
}

function innerHtml(element, res, body) {
  element.innerHTML = "<div>" + body + "</div>";
  res.send("<p>" + body + "</p>");
}

function hostRedirect(res, req) {
  res.redirect("https://" + req.get("host") + "/next");
}

function mixedCrypto(password) {
  const token = Math.random();
  const digest = createHash("md5").update(password).digest("hex");
  return createCipheriv("aes-256-cbc", digest, "0123456789abcdef");
}

function compareSecrets(req) {
  if (req.body.password == req.body.cpassword) return false;
  return req.body.token == md5(req.body.login);
}

function buildRegex(req) {
  return new RegExp(req.query.q);
}

function openSession(session) {
  return session({ secret: "keyboard cat", resave: false, saveUninitialized: false });
}

function forgeReset(req) {
  return req.query.token == createHash("md5").update(req.query.login).digest("hex");
}

function publishUsers(res, db) {
  return db.User.findAll({}).then(function (users) {
    res.json(users);
  });
}

function connectDb(config) {
  if (process.env.DATABASE_URL) return new Sequelize(process.env.DATABASE_URL);
  return new Sequelize(config.database, config.username, config.password, {
    host: config.host,
    dialect: config.dialect,
  });
}

function mountAdmin(router, auth) {
  router.get("/admin/users", auth.isAuthenticated, auth.listUsers);
}

function saveUser(req, db) {
  return db.User.find({ where: { id: req.body.id } }).then(function (user) {
    user.email = req.body.email;
    return user.save();
  });
}

function runEquation(mathjs, req) {
  return mathjs.eval(req.body.eqn);
}

function guardedEquation(mathjs, req) {
  try {
    return mathjs.eval(req.body.eqn);
  } catch (err) {
    return "Invalid Equation";
  }
}

function bootApp() {
  const app = express();
  app.get("/", function (req, res) {
    res.send("ok");
  });
  return app;
}

function failedLogin(done) {
  return done(null, false, "Invalid Credentials");
}

function exportRoutes(router, editUser) {
  router.post("/useredit", editUser);
}
