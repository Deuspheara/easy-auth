"use strict";
const onCallback = location.pathname === "/oidc/callback";
let returned = readCallback();
const form = document.getElementById("signin-form");
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
  } finally { history.replaceState(null, "", location.pathname); }
}
function render() {
  form.hidden = closed || (onCallback && !returned);
  document.getElementById("continue").textContent = onCallback ? "Confirm provider sign-in" : "Continue to provider";
  for (const button of document.querySelectorAll("button")) button.disabled = busy;
}
status.textContent = onCallback
  ? returned ? "Provider returned. Confirm to verify its proof and sign in." : "No usable callback is available. Cancel before starting again."
  : "Continue to your configured provider. Sign out of any current account first.";
render();
async function request(action, body, signal) {
  const response = await fetch(`/v1/oidc/sign-in/${action}`, {
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
    if (!closed && stamp === generation) status.textContent = "The operation was not confirmed. No sign-in success is established. Check your session if completion was interrupted; cancel before starting again.";
  } finally {
    if (stamp === generation) { busy = false; controller = null; render(); }
  }
}
form.addEventListener("submit", event => {
  event.preventDefault();
  run(async (signal, current) => {
    if (onCallback) {
      if (!returned) return;
      const proof = returned;
      returned = null;
      await request("finish", proof, signal);
      if (current()) status.textContent = "Provider sign-in completed. Your local session is available.";
    } else {
      const response = await request("start", {}, signal);
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
  if (current()) status.textContent = "Pending sign-in cancelled. Any current session was retained.";
}));
window.addEventListener("pagehide", () => {
  closed = true; generation += 1; returned = null;
  controller?.abort(); controller = null; busy = false;
});
window.addEventListener("pageshow", event => {
  if (event.persisted) {
    closed = false;
    status.textContent = "Page restored without callback proof. Check your session, then cancel before restarting.";
    render();
  }
});
