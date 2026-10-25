import {clearAddress, request, failure,  createKey, assertKey} from "./shared.js";
import {recoveryOperation, feedback, recoveryAccountId} from "/ui/recovery-view.js";
import {renderClaim} from "/ui/recovery-claim-view.js";
clearAddress();
const account = document.getElementById("account");
const code = document.getElementById("code");
const cancelCode = document.getElementById("cancel-code");
let claim = null;
let completed = false;
function target() {
  if (!claim) throw new Error("Resume a request first");
  return {account_id: claim.account_id, claim_id: claim.claim_id};
}
function render(busy = false) { renderClaim(claim, busy, completed); }
function show(owner, info) { claim = {...info, account_id: owner}; render(true); }
const run = recoveryOperation(failure, render);
account.addEventListener("input", () => { claim = null; completed = false; render(); });
document.getElementById("logout").addEventListener("click", event => run(event.currentTarget, async () => {
  await request("/v1/logout", {});
  feedback("Signed out in this browser. The independent recovery binding is retained.");
}));
document.getElementById("start-form").addEventListener("submit", event => {
  event.preventDefault();
  run(event.currentTarget, async () => {
    try {
      const owner = recoveryAccountId(account);
      await request("/v1/passkeys/recovery/browser", {});
      const info = await request("/v1/passkeys/recovery/claims/start", {account_id: owner, code: code.value});
      show(owner, info); feedback("Request reserved. Keep this browser. Use Resume if a response is lost.");
    } finally { code.value = ""; }
  });
});
document.getElementById("resume").addEventListener("click", event => run(event.currentTarget, async () => {
  const owner = recoveryAccountId(account);
  const info = await request("/v1/passkeys/recovery/claims/resume", {account_id: owner});
  show(owner, info); feedback("Original request resumed without extending its deadline.");
}));
document.getElementById("refresh").addEventListener("click", event => run(event.currentTarget, async () => {
  const info = await request("/v1/passkeys/recovery/claims/status", target());
  show(claim.account_id, info); feedback("Status refreshed. Only the server can authorize completion.");
}));
document.getElementById("browser-cancel-form").addEventListener("submit", event => {
  event.preventDefault();
  run(event.currentTarget, async () => {
    await request("/v1/passkeys/recovery/claims/cancel", target());
    claim = null; feedback("Request cancelled. The code remains consumed. Use a working key to configure new proof.");
  });
});
document.getElementById("code-cancel-form").addEventListener("submit", event => {
  event.preventDefault();
  run(event.currentTarget, async () => {
    try {
      await request("/v1/passkeys/recovery/claims/cancel-with-code", {account_id: recoveryAccountId(account), code: cancelCode.value});
      claim = null; feedback("Current request cancelled. The retained code remains consumed; no sign-in was granted.");
    } finally { cancelCode.value = ""; }
  });
});
document.getElementById("replace-form").addEventListener("submit", event => {
  event.preventDefault();
  run(event.currentTarget, async () => {
    const bound = target();
    feedback("Create the replacement passkey, then complete its separate verification prompt.");
    const creation = await request("/v1/passkeys/recovery/replacement/start", bound);
    const registration = await createKey(creation.options);
    const assertion = await request("/v1/passkeys/recovery/replacement/registration", {...bound, transaction_id: creation.transaction_id, credential: registration});
    const credential = await assertKey(assertion.options);
    await request("/v1/passkeys/recovery/replacement/finish", {...bound, transaction_id: assertion.transaction_id, credential});
    claim = null; completed = true; render(true);
    feedback("Recovery complete. Previous keys and sessions were invalidated. Configure a new saved code with your replacement key now.");
  });
});
window.addEventListener("pagehide", () => { code.value = ""; cancelCode.value = ""; claim = null; });
render();
