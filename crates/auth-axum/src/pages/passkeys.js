"use strict";
import {request, createKey} from "/ui/browser-operations.js";
import {element, announce, notify, errorMessage, submit, run} from "/ui/view.js";
import {currentView, requireView} from "/ui/account.js";
import {showAccountPanel} from "/ui/account-view.js";
import {keyRow} from "/ui/passkey-row.js";

let requireCurrent;
let refresh;
let verify;
let inventoryAvailable = false;

export function bindPasskeys(refreshAccount, checkAccount, caps, verifyAccount) {
  refresh = refreshAccount;
  requireCurrent = checkAccount;
  verify = verifyAccount;
  for (const id of ["refresh-passkeys", "retry-passkeys"]) element(id).addEventListener("click", () => {
    showAccountPanel("passkeys");
    void run(element(id), async () => {
      const loaded = await loadPasskeys(caps, id === "retry-passkeys");
      if (!element("account").hidden) announce(loaded ? "" : element("passkeys-state").textContent);
    }, "Checking passkey access…");
  });
  for (const id of ["add-passkey", "enroll-passkey-entry"]) element(id).addEventListener("click", () => {
    showAccountPanel("passkeys");
    element("enrollment-form").hidden = false;
    element("key-label").focus();
  });
  submit("enrollment-form", async () => {
    const user = await requireCurrent();
    const current = currentView();
    const started = await request("/v1/passkeys/enrollment/start", {label: element("key-label").value, discoverable: true});
    const credential = await createKey(started.options);
    await requireCurrent();
    requireView(current);
    await request("/v1/passkeys/enrollment/finish", {transaction_id: started.transaction_id, credential});
    element("enrollment-form").hidden = true;
    element("key-label").value = "";
    const refreshed = await refresh();
    if (refreshed?.id !== user.id) return;
    notify(caps.passkeyManagement && !inventoryAvailable
      ? "Passkey added. Verify access to view and manage your registered passkeys."
      : "Passkey added. Use it once to verify it works.");
  }, "Create your additional passkey…");
}

export async function loadPasskeys(caps, verifyFresh = false) {
  inventoryAvailable = false;
  if (!caps.passkeyManagement) return false;
  const current = currentView();
  element("passkeys-state").textContent = "Checking passkey access…";
  element("retry-passkeys").hidden = true;
  try {
    const inventory = await request("/v1/passkeys");
    await requireCurrent();
    if (!current()) return false;
    showAccountPanel("passkeys", false);
    element("passkeys").replaceChildren();
    for (const key of inventory.passkeys) element("passkeys").append(keyRow(key, current, requireCurrent, refresh));
    inventoryAvailable = true;
    element("passkeys-summary").textContent = inventory.passkeys.length + (inventory.passkeys.length === 1 ? " registered passkey" : " registered passkeys");
    element("passkeys-state").textContent = inventory.passkeys.length ? "" : "No passkeys registered. Add one to sign in with your device.";
    return true;
  } catch (error) {
    if (!current()) return false;
    if (error.status === 401 && caps.passkeySignin) {
      await requireCurrent();
      requireView(current);
      if (verifyFresh) {
        const result = await verify();
        if (result === "pending") return false;
      }
      element("passkeys-state").textContent = verifyFresh
        ? "Verification cancelled. Your current sign-in is unchanged."
        : "Verify access with a passkey to view your registered keys. You can still add a key with your current sign-in when permitted.";
    } else element("passkeys-state").textContent = errorMessage(error);
    element("retry-passkeys").textContent = error.status === 401 && caps.passkeySignin ? "Verify access" : "Try again";
    element("retry-passkeys").hidden = false;
    return false;
  }
}
