"use strict";
const onCallback = location.pathname === "/google/callback";
const deletion = document.body.dataset.flow === "delete";
const endpoint = deletion ? "/v1/account/google-delete" : "/v1/google/sign-in";
const form = document.getElementById("confirm-form");
const confirmation = document.getElementById("confirmation");
const status = document.getElementById("status");
let returned = readCallback();
let generation = 0;
let closed = false;
let busy = false;
let controller = null;

function readCallback() {
  try {
    const raw = location.search.slice(1);
    const bytes = value => new TextEncoder().encode(value).length;
    if (!onCallback || !raw || bytes(raw) > 8192 || location.hash || /%(?![0-9a-f]{2})/i.test(raw)) return null;
    const params = new URLSearchParams(raw);
    const allowed = new Set(["state", "iss", "code", "error", "error_description", "error_uri", "scope", "authuser", "hd", "prompt", "session_state"]);
    for (const [name, value] of params) {
      if (!allowed.has(name) || params.getAll(name).length !== 1 || bytes(value) > 2048 || /[\u0000-\u001f\u007f-\u009f\ufffd]/u.test(value)) return null;
    }
    if (!/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(params.get("state") ?? "") || params.get("iss") !== "https://accounts.google.com") return null;
    const code = params.get("code");
    const error = params.get("error");
    if (code !== null) {
      if (!code || !/^[\x20-\x7e]+$/.test(code) || error !== null || params.has("error_description") || params.has("error_uri")) return null;
    } else if (!error || !/^[\x20-\x7e]+$/.test(error)) return null;
    return {query: raw};
  } finally { history.replaceState(null, "", location.pathname); }
}
function render() {
  form.hidden = closed || (onCallback && !returned);
  document.getElementById("continue").textContent = onCallback
    ? deletion ? "Confirm Google return and delete my account" : "Confirm Google return"
    : deletion ? "Continue to Google for deletion proof" : "Continue to Google";
  for (const element of document.querySelectorAll("button,input")) element.disabled = busy;
}
status.textContent = onCallback
  ? returned ? "Google returned. Confirm to verify this result; no sign-in or deletion has occurred." : "No usable callback is available. Cancel before restarting."
  : deletion ? "Confirm to request Google proof. Starting does not delete the account or force fresh Google authentication." : "Sign out of any current account before continuing.";
render();

async function request(action, body, signal) {
  const response = await fetch(`${endpoint}/${action}`, {
    method: "POST", credentials: "same-origin", cache: "no-store", redirect: "error", signal,
    headers: {"Content-Type": "application/json"}, body: JSON.stringify(body)
  });
  if (!response.ok) throw Object.assign(new Error("Request not confirmed"), {status: response.status});
  if (action !== "start" && response.status !== 204) throw new Error("Unexpected completion");
  return response.status === 204 ? null : response.json();
}
async function run(action) {
  if (closed || busy) return;
  busy = true;
  const stamp = generation;
  controller = new AbortController();
  render();
  try { await action(controller.signal, () => !closed && stamp === generation); }
  catch (error) {
    if (!closed && stamp === generation) {
      const reason = error.status === 503 ? "Service or Google profile unavailable." : error.status === 429 ? "Too many attempts; wait before restarting." : "The operation was not confirmed.";
      status.textContent = `${reason} No sign-in or deletion is confirmed here. Check your session/account if completion was interrupted; cancel before restarting.`;
    }
  } finally {
    if (stamp === generation) {busy = false; controller = null; render();}
  }
}
form.addEventListener("submit", event => {
  event.preventDefault();
  run(async (signal, current) => {
    const intent = deletion ? {confirmation: confirmation.value} : {};
    if (deletion && intent.confirmation !== "delete my account") throw new Error("Confirmation required");
    if (onCallback) {
      if (!returned) return;
      const proof = returned;
      returned = null;
      if (confirmation) confirmation.value = "";
      await request("finish", {...intent, ...proof}, signal);
      if (current()) status.textContent = deletion ? "Account deletion committed. Local session authority was removed." : "Google sign-in completed. Your local session is available.";
    } else {
      const response = await request("start", intent, signal);
      if (!current()) return;
      const destination = new URL(response.authorization_url);
      if (destination.origin !== "https://accounts.google.com" || destination.username || destination.password || destination.hash) throw new Error("Invalid Google redirect");
      location.assign(destination.href);
    }
  });
});
document.getElementById("cancel").addEventListener("click", () => run(async (signal, current) => {
  returned = null;
  if (confirmation) confirmation.value = "";
  await request("cancel", {}, signal);
  if (current()) status.textContent = "Pending attempt cancelled. Any current session was retained.";
}));
window.addEventListener("pagehide", () => {
  closed = true; generation += 1; returned = null;
  if (confirmation) confirmation.value = "";
  controller?.abort(); controller = null; busy = false;
});
window.addEventListener("pageshow", event => {
  if (event.persisted) {closed = false; status.textContent = "Page restored without callback proof. Check your session/account and cancel before restarting."; render();}
});
