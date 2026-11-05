function safeQueryTemplate(orderId, sort) {
  return queryWithBinding(orderSql, [orderId, sort]);
}

function safeQueryNosql(users, id) {
  return users.find({ id: id });
}

function safeQueryLdap(req) {
  return search(escapeFilter(req.query.user));
}

function safeFetchUrl(http) {
  return http.get("https://example.com/orders");
}

function safeWriteHeader(res, mailer, csv) {
  res.setHeader("X-File", "report.txt");
  console.log("ready");
  mailer.sendMail({ subject: "ready" });
  csv.writeCsv(["ready"]);
}

function safeSetSessionCookie(res, id) {
  res.cookie("session", id, { httpOnly: true, secure: true, sameSite: "lax" });
}

function safeAcceptJwt(jwt, token, secret) {
  return jwt.verify(token, secret, { algorithms: ["HS256"] });
}

function safeTrustTls(https) {
  return https.get("https://example.com/orders", { rejectUnauthorized: true, minVersion: "TLSv1.2" });
}

function safeCopyRole(user) {
  user.role = "reader";
}

function safeOpenCors(cors, frame, payload) {
  frame.postMessage(payload, "https://app.example");
  return cors({ origin: "https://app.example", credentials: true });
}

function safeStoreToken() {
  localStorage.setItem("theme", "dark");
}

function safeLogPassword(userId) {
  console.log("signed in", userId);
}

function safeSendError(res) {
  res.send("Something went wrong");
}

function safeRenderTemplate(ejs, name) {
  return ejs.render("<p><%= name %></p>", { name: name });
}

function safeLoadYaml(yaml, payload) {
  return yaml.safeLoad(payload);
}

function safeInnerHtml(element, res, body) {
  element.textContent = body;
  res.send("Saved");
}

function safeHostRedirect(res) {
  res.redirect("/orders");
}

function safeMixedCrypto(password) {
  const token = randomBytes(16);
  const digest = createHash("sha256").update(password).digest();
  return createCipheriv("aes-256-gcm", digest, randomBytes(12));
}

function safeBuildRegex() {
  return new RegExp("^[a-z]+$");
}

const csurf = require("csurf");

function safeOpenSession(session) {
  return session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false });
}

function safeForgeReset(req, stored) {
  return timingSafeEqual(Buffer.from(req.body.token), stored);
}

function safePublishUsers(res, db) {
  return db.User.findAll({ attributes: ["id", "name", "email"] }).then(function (users) {
    res.json(users);
  });
}

function safeConnectDb(config) {
  return new Sequelize(config.database, config.username, config.password, {
    host: config.host,
    dialect: config.dialect,
    logging: false,
  });
}

function safeMountAdmin(router, auth) {
  router.get("/admin/users", auth.isAuthenticated, auth.adminCheck, auth.listUsers);
}

function safeSaveUser(req, db) {
  return db.User.find({ where: { id: req.user.id } }).then(function (user) {
    user.email = req.body.email;
    return user.save();
  });
}

function safeFailedLogin(done, username) {
  console.warn("failed login", username);
  return done(null, false);
}

function safeBootApp() {
  const app = express();
  app.disable("x-powered-by");
  app.use(csurf());
  app.use(function (err, req, res, next) {
    res.status(500).send("Something went wrong");
  });
  app.post("/useredit", function (req, res) {
    res.send("ok");
  });
  return app;
}
