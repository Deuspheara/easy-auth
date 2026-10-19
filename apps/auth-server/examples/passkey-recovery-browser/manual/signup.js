import {request, createKey, assertKey, failure, clearAddress} from "/passkey-recovery/shared.js";
clearAddress();
const status = document.getElementById("status");
let busy = false;
async function run(action) {
  if (busy) return;
  busy = true;
  status.textContent = "Working…";
  for (const control of document.querySelectorAll("button,input")) control.disabled = true;
  try { await action(); }
  catch (error) { status.textContent = failure(error); }
  finally {
    busy = false;
    for (const control of document.querySelectorAll("button,input")) control.disabled = false;
  }
}
const supported = typeof globalThis.PublicKeyCredential?.parseCreationOptionsFromJSON === "function"
  && typeof globalThis.PublicKeyCredential?.parseRequestOptionsFromJSON === "function"
  && typeof globalThis.PublicKeyCredential?.prototype.toJSON === "function";
status.textContent = supported ? "Ready for actual platform or security-key prompts. Creating a passkey alone does not sign in; its separate assertion must succeed." : "This browser lacks the required native WebAuthn JSON support. No weaker fallback is available.";
document.getElementById("signup-form").addEventListener("submit", event => {
  event.preventDefault();
  run(async () => {
    if (!supported) throw Object.assign(new Error("Unsupported browser"), {name: "UnsupportedPasskeyClient"});
    const pending = await request("/v1/passkeys/signup/start", {display_name: "AUTH-20 device test"});
    const credential = await createKey(pending.options);
    const assertion = await request("/v1/passkeys/signup/registration", {transaction_id: pending.transaction_id, credential});
    const signed = await assertKey(assertion.options);
    await request("/v1/passkeys/signup/finish", {transaction_id: pending.transaction_id, credential: signed});
    const user = await request("/v1/session");
    document.getElementById("owner").textContent = user.id;
    status.textContent = "Actual registration and signed assertion succeeded. Continue to recovery code configuration; retain the public account ID with your offline code.";
  });
});
document.getElementById("logout").addEventListener("click", () => run(async () => {
  await request("/v1/logout", {});
  document.getElementById("owner").textContent = "None";
  status.textContent = "Signed out of this disposable fixture.";
}));
