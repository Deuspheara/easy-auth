import {clearAddress, request, failure,  assertKey} from "./shared.js";
import {recoveryOperation, feedback, recoveryAccountId} from "/ui/recovery-view.js";
import {showSetupStep, resetPreparedStep, updateSetupSearch} from "/ui/recovery-setup-view.js";
import {fieldError} from "/ui/feedback.js";
clearAddress();
const account = document.getElementById("account");
const kit = document.getElementById("kit");
const displayed = document.getElementById("saved-code");
const reentered = document.getElementById("reentered-code");
let pending = null;

function clearKit() {
  resetPreparedStep();
  pending = null; displayed.value = ""; reentered.value = ""; kit.hidden = true;
  document.getElementById("saved-consent").checked = false;
}
async function profile() {
  const user = await request("/v1/session");
  account.value = user.id;
  document.getElementById("owner").textContent = user.id;
  void updateSetupSearch(user);
  return user;
}
const run = recoveryOperation(failure);
document.getElementById("use-session").addEventListener("click", event => {
  run(event.currentTarget, async () => { await profile(); showSetupStep(1, true, false); });
});
document.getElementById("prepare-again").addEventListener("click", () => {
  if (document.querySelector('[aria-busy="true"]')) return;
  clearKit(); showSetupStep(1, true, false);
});
document.getElementById("signin-form").addEventListener("submit", event => {
  event.preventDefault();
  run(event.currentTarget, async () => {
    clearKit(); feedback("Verify your working passkey.");
    const start = await request("/v1/passkeys/authentication/start", {mode: "account_bound", account_id: recoveryAccountId(account)});
    const credential = await assertKey(start.options);
    await request("/v1/passkeys/authentication/finish", {transaction_id: start.transaction_id, credential});
    await profile(); showSetupStep(1); feedback("Passkey sign-in complete. You may configure a saved code or cancel your current recovery request.");
  });
});
document.getElementById("prepare-form").addEventListener("submit", event => {
  event.preventDefault();
  run(event.currentTarget, async () => {
    clearKit(); await profile();
    const prepared = await request("/v1/passkeys/recovery/code/prepare", {});
    pending = {id: prepared.id}; // Keep no second code copy in page state.
    displayed.value = prepared.code; prepared.code = null;
    showSetupStep(2);
    feedback("Save the account ID and code offline, then reenter the code to confirm. It is not active yet.");
  });
});
document.getElementById("confirm-form").addEventListener("submit", event => {
  event.preventDefault();
  run(event.currentTarget, async () => {
    if (!pending) return;
    if (reentered.value !== displayed.value) {
      reentered.value = ""; fieldError(reentered, "The copies do not match. Reenter your offline copy."); reentered.focus(); return;
    }
    try {
      await request("/v1/passkeys/recovery/code/confirm", {id: pending.id, code: reentered.value});
      clearKit(); showSetupStep(3); feedback("Saved code confirmed. Previous recovery configuration is replaced. Keep the account ID and code offline.");
    } finally { reentered.value = ""; }
  });
});
document.getElementById("cancel-form").addEventListener("submit", event => {
  event.preventDefault();
  run(event.currentTarget, async () => {
    await request("/v1/passkeys/recovery/claims/cancel-with-key", {});
    feedback("Current recovery cancelled. Its code stays consumed. Configure a replacement code with your working key.");
    document.getElementById("cancel-consent").checked = false;
  });
});
window.addEventListener("pagehide", clearKit);
request("/v1/session").then(user => {
  void updateSetupSearch(user);
  if (!document.querySelector('[aria-busy="true"]') && !pending && account.value === "") {
    account.value = user.id;
    document.getElementById("owner").textContent = user.id;
  }
}).catch(() => {
  void updateSetupSearch(null);
  if (!document.querySelector('[aria-busy="true"]')) feedback("Enter your retained public account ID and sign in freshly with a passkey.");
});
