import {clearAddress, request, failure, accountId, createKey, assertKey} from "./shared.js";
clearAddress();
const account = document.getElementById("account");
const status = document.getElementById("status");
const code = document.getElementById("code");
const cancelCode = document.getElementById("cancel-code");
let claim = null;
let busy = false;
function target() {
  if (!claim) throw new Error("Resume a request first");
  return {account_id: claim.account_id, claim_id: claim.claim_id};
}
function render() {
  document.getElementById("claim").hidden = !claim;
  document.getElementById("replace").disabled = busy || !claim?.ready;
  if (!claim) return;
  const date = value => new Date(value).toLocaleString();
  document.getElementById("timing").textContent = `Expires: ${date(claim.expires_at_ms)}. ${claim.not_before_ms === null ? "Waiting for required notification acceptance." : `Earliest completion: ${date(claim.not_before_ms)}.`} ${claim.ready ? "Server reports eligibility; every replacement step still rechecks authority." : "Not eligible yet."}`;
  document.getElementById("notification").textContent = claim.notification_required ? "A verified contact is required for the start notice. SMTP acceptance is not proof of readership." : "No independent email alert exists for this account.";
}
function show(owner, info) { claim = {...info, account_id: owner}; render(); }
async function run(action) {
  if (busy) return;
  busy = true;
  status.textContent = "Working…";
  for (const button of document.querySelectorAll("button,input")) button.disabled = true;
  try { await action(); }
  catch (error) { status.textContent = failure(error); }
  finally {
    busy = false;
    for (const button of document.querySelectorAll("button,input")) button.disabled = false;
    render();
  }
}
account.addEventListener("input", () => { claim = null; render(); });
document.getElementById("logout").addEventListener("click", () => run(async () => {
  await request("/v1/logout", {});
  status.textContent = "Signed out in this browser. The independent recovery binding is retained.";
}));
document.getElementById("start-form").addEventListener("submit", event => {
  event.preventDefault();
  run(async () => {
    try {
      const owner = accountId(account);
      await request("/v1/passkeys/recovery/browser", {});
      const info = await request("/v1/passkeys/recovery/claims/start", {account_id: owner, code: code.value});
      show(owner, info); status.textContent = "Request reserved. Keep this browser. Use Resume if a response is lost.";
    } finally { code.value = ""; }
  });
});
document.getElementById("resume").addEventListener("click", () => run(async () => {
  const owner = accountId(account);
  const info = await request("/v1/passkeys/recovery/claims/resume", {account_id: owner});
  show(owner, info); status.textContent = "Original request resumed without extending its deadline.";
}));
document.getElementById("refresh").addEventListener("click", () => run(async () => {
  const info = await request("/v1/passkeys/recovery/claims/status", target());
  show(claim.account_id, info); status.textContent = "Status refreshed. Only the server can authorize completion.";
}));
document.getElementById("browser-cancel-form").addEventListener("submit", event => {
  event.preventDefault();
  run(async () => {
    await request("/v1/passkeys/recovery/claims/cancel", target());
    claim = null; status.textContent = "Request cancelled. The code remains consumed. Use a working key to configure new proof.";
  });
});
document.getElementById("code-cancel-form").addEventListener("submit", event => {
  event.preventDefault();
  run(async () => {
    try {
      await request("/v1/passkeys/recovery/claims/cancel-with-code", {account_id: accountId(account), code: cancelCode.value});
      claim = null; status.textContent = "Current request cancelled. The retained code remains consumed; no sign-in was granted.";
    } finally { cancelCode.value = ""; }
  });
});
document.getElementById("replace-form").addEventListener("submit", event => {
  event.preventDefault();
  run(async () => {
    const bound = target();
    status.textContent = "Create the replacement passkey, then complete its separate verification prompt.";
    const creation = await request("/v1/passkeys/recovery/replacement/start", bound);
    const registration = await createKey(creation.options);
    const assertion = await request("/v1/passkeys/recovery/replacement/registration", {...bound, transaction_id: creation.transaction_id, credential: registration});
    const credential = await assertKey(assertion.options);
    await request("/v1/passkeys/recovery/replacement/finish", {...bound, transaction_id: assertion.transaction_id, credential});
    claim = null;
    status.textContent = "Recovery complete. Previous keys and sessions were invalidated. Configure a new saved code with your replacement key now.";
  });
});
window.addEventListener("pagehide", () => { code.value = ""; cancelCode.value = ""; claim = null; });
render();
