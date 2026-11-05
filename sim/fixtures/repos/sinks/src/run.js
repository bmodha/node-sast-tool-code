function runUserExpression(source) {
  return eval(source);
}

function runCommand(command) {
  const childProcess = require("child_process");
  childProcess.exec(command);
}

function runMemberEval(mathjs, eqn) {
  return mathjs.eval(eqn);
}

function readPayload(serialize, payload) {
  return serialize.unserialize(payload);
}

function go(res, req) {
  res.redirect(req.query.url);
}

function readXml(libxmljs, xml) {
  return libxmljs.parseXmlString(xml, { noent: true });
}

function checkToken(req) {
  return req.query.token == md5(req.query.login);
}
