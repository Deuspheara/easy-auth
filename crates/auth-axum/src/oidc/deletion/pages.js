"use strict";
const callbackPath = "/oidc/account-delete/callback";
const onCallback = location.pathname === callbackPath || location.pathname === "/oidc/callback";
let returned = readCallback();
const form = document.getElementById("confirm-form");
const confirmation = document.getElementById("confirmation");
const status = document.getElementById("status");
let generation = 0;
let closed = false;
let busy = false;
let controller = null;
function readCallback() {
  try {
    if (!onCallback || location.search.length > 8192 || location.hash || /%(?![0-9a-f]{2})/i.test(location.search)) return null;
    const params = new URLSearchParams(location.search);
    const allowed = new Set(["state", "code", "iss", "session_state"]);
    for (const key of params.keys()) {
      if (!allowed.has(key) || params.getAll(key).length !== 1 || params.get(key).length > 2048) return null;
    }
    const state = params.get("state");
    const code = params.get("code");
    const issuer = params.get("iss");
    if (!/^[A-Za-z0-9_-]{43}$/.test(state ?? "") || !code || !/^[\x20-\x7e]+$/.test(code)) return null;
    return {state, code, ...(issuer === null ? {} : {issuer})};
  } finally {
    // No callback proof persists in history, DOM, logs or browser storage.
    history.replaceState(null, "", location.pathname);
  }
}
function render() {
  form.hidden = closed || (onCallback && !returned);
  document.getElementById("confirm").textContent = onCallback ? "Permanently delete my account" : "Reauthenticate with provider";
  for (const element of document.querySelectorAll("button,input")) element.disabled = busy;
}
status.textContent = onCallback
  ? returned ? "Provider returned. Confirm again to verify its proof and delete the account." : "No usable callback is available. Cancel this attempt before starting again."
  : "Confirm to request fresh authentication from your configured provider. This step does not delete the account.";
render();
async function request(action, body, signal) {
  const response = await fetch(`/v1/account/provider-delete/${action}`, {
    method: "POST", credentials: "same-origin", cache: "no-store", redirect: "error", signal,
    headers: {"Content-Type": "application/json"}, body: JSON.stringify(body)
  });
  if (!response.ok) throw new Error("Request not confirmed");
  return response.status === 204 ? null : response.json();
}
async function run(action) {
  if (closed || busy) return;
  busy = true;
  const stamp = generation;
  controller = new AbortController();
  render();
  try { await action(controller.signal, () => !closed && stamp === generation); }
  catch {
    if (!closed && stamp === generation) status.textContent = "The operation was not confirmed. No deletion success is established. Cancel the pending attempt before restarting.";
  } finally {
    if (stamp === generation) { busy = false; controller = null; confirmation.value = ""; render(); }
  }
}
form.addEventListener("submit", event => {
  event.preventDefault();
  if (confirmation.value !== "delete my account") return;
  run(async (signal, current) => {
    const phrase = confirmation.value;
    confirmation.value = "";
    if (onCallback) {
      if (!returned) return;
      const proof = returned;
      returned = null;
      await request("finish", {confirmation: phrase, ...proof}, signal);
      if (current()) { form.hidden = true; status.textContent = "Account deletion completed. Its sessions were invalidated."; }
    } else {
      const response = await request("start", {confirmation: phrase}, signal);
      if (!current()) return;
      const destination = new URL(response.authorization_url);
      if (destination.protocol !== "https:") throw new Error("Invalid provider redirect");
      location.assign(destination.href);
    }
  });
});
document.getElementById("cancel").addEventListener("click", () => run(async (signal, current) => {
  returned = null;
  await request("cancel", {}, signal);
  if (current()) status.textContent = "Pending deletion cancelled. No account was deleted by cancellation.";
}));
window.addEventListener("pagehide", () => {
  closed = true; generation += 1; returned = null; confirmation.value = "";
  controller?.abort(); controller = null; busy = false;
});
window.addEventListener("pageshow", event => {
  if (event.persisted) {
    closed = false;
    status.textContent = "Page restored without callback proof. Cancel the attempt before restarting.";
    render();
  }
});
