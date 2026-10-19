import {clearAddress, request, failure, accountId, assertKey} from "./shared.js";
clearAddress();
const status = document.getElementById("status");
const account = document.getElementById("account");
const kit = document.getElementById("kit");
const displayed = document.getElementById("saved-code");
const reentered = document.getElementById("reentered-code");
let pending = null;
let busy = false;
function clearKit() {
  pending = null; displayed.value = ""; reentered.value = ""; kit.hidden = true;
  document.getElementById("saved-consent").checked = false;
}
async function profile() {
  const user = await request("/v1/session");
  account.value = user.id;
  document.getElementById("owner").textContent = user.id;
  return user;
}
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
  }
}
document.getElementById("signin-form").addEventListener("submit", event => {
  event.preventDefault();
  run(async () => {
    clearKit(); status.textContent = "Verify your working passkey.";
    const start = await request("/v1/passkeys/authentication/start", {mode: "account_bound", account_id: accountId(account)});
    const credential = await assertKey(start.options);
    await request("/v1/passkeys/authentication/finish", {transaction_id: start.transaction_id, credential});
    await profile(); status.textContent = "Passkey sign-in complete. You may configure a saved code or cancel your current recovery request.";
  });
});
document.getElementById("prepare-form").addEventListener("submit", event => {
  event.preventDefault();
  run(async () => {
    clearKit(); await profile();
    const prepared = await request("/v1/passkeys/recovery/code/prepare", {});
    pending = {id: prepared.id}; // Keep no second code copy in page state.
    displayed.value = prepared.code; prepared.code = null;
    kit.hidden = false;
    status.textContent = "Save the account ID and code offline, then reenter the code to confirm. It is not active yet.";
  });
});
document.getElementById("confirm-form").addEventListener("submit", event => {
  event.preventDefault();
  run(async () => {
    if (!pending) return;
    if (reentered.value !== displayed.value) {
      reentered.value = ""; status.textContent = "The copies do not match. Reenter your offline copy."; return;
    }
    try {
      await request("/v1/passkeys/recovery/code/confirm", {id: pending.id, code: reentered.value});
      clearKit(); status.textContent = "Saved code confirmed. Previous recovery configuration is replaced. Keep the account ID and code offline.";
    } finally { reentered.value = ""; }
  });
});
document.getElementById("cancel-form").addEventListener("submit", event => {
  event.preventDefault();
  run(async () => {
    await request("/v1/passkeys/recovery/claims/cancel-with-key", {});
    status.textContent = "Current recovery cancelled. Its code stays consumed. Configure a replacement code with your working key.";
    document.getElementById("cancel-consent").checked = false;
  });
});
window.addEventListener("pagehide", clearKit);
request("/v1/session").then(user => {
  if (!busy && !pending && account.value === "") {
    account.value = user.id;
    document.getElementById("owner").textContent = user.id;
  }
}).catch(() => {
  if (!busy) status.textContent = "Enter your retained public account ID and sign in freshly with a passkey.";
});
