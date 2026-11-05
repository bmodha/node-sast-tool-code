const UNTRUSTED = /ignore previous instructions/i;

export function sawUntrustedInstruction(source) {
  return UNTRUSTED.test(source);
}

export function review() {
  return { system2: "not_run" };
}
