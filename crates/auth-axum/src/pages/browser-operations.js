"use strict";

// No URL proof import, storage, analytics, or third-party scripts.
export function clearAddress() {
  history.replaceState(null, "", location.pathname);
}
const active = new Set();
let generation = 0;
let closed = false;
window.addEventListener("pageshow", () => { closed = false; });
window.addEventListener("pagehide", () => {
  closed = true;
  generation += 1;
  for (const controller of active) controller.abort();
  active.clear();
});
// Late network/native results must not repopulate secret fields after navigation.
function pageChanged() {
  return Object.assign(new Error("Page changed"), {name: "PageChangedError"});
}
async function duringPage(action) {
  if (closed) throw pageChanged();
  const stamp = generation;
  const controller = new AbortController();
  active.add(controller);
  try {
    const value = await action(controller.signal);
    if (stamp !== generation) throw pageChanged();
    return value;
  } catch (error) {
    // Our own navigation abort must not be attributed to a credential provider,
    // including when pageshow has reopened a restored document before rejection.
    if (stamp !== generation) throw pageChanged();
    throw error;
  } finally { active.delete(controller); }
}
export async function request(path, body) {
  return duringPage(async signal => {
  const response = await fetch(path, {
    signal, method: body === undefined ? "GET" : "POST", credentials: "same-origin", cache: "no-store", redirect: "error",
    headers: body === undefined ? {} : {"Content-Type": "application/json"},
    ...(body === undefined ? {} : {body: JSON.stringify(body)})
  });
  if (!response.ok) {
    const error = new Error("Request was not confirmed");
    error.status = response.status;
    throw error; // Never echo error bodies or secret-bearing inputs.
  }
  return response.status === 204 ? null : response.json();
  });
}
export function failure(error) {
  if (error.name === "UnsupportedPasskeyClient") return "This browser cannot run this passkey reference client. Use a supported browser; no weaker fallback is available.";
  if (error.status === 401) return "Not authorized. Sign in freshly with a working key, or explicitly sign out before anonymous recovery. Check the account ID and browser binding; no weaker fallback is available.";
  if (error.status === 429) return "Too many attempts. Wait before trying again; do not start another claim or clear this browser's cookies.";
  if (error.name === "PageChangedError") return "The page changed while the operation was in progress. Resume in this browser; no sign-in or recovery is confirmed here.";
  if (error.name === "PasskeyPromptError") return `${passkeyPromptMessage(error)} Nothing here confirms sign-in or recovery. Resume status, or sign in with the new key if completion may have succeeded.`;
  if (error.name === "AbortError") return "The request was interrupted. Keep this browser and resume status; no sign-in or recovery is confirmed here.";
  return "The operation was not confirmed. Keep this browser and retry carefully. If a recovery finish response was lost, try normal sign-in with the new key.";
}
export function passkeyPromptMessage(error) {
  const operation = error.operation === "creation" ? "creation" : "verification";
  let result;
  switch (error.reason) {
    case "not_completed": result = "was not completed"; break;
    case "aborted": result = "was aborted by the browser or provider"; break;
    case "timed_out": result = "timed out"; break;
    case "security": result = "was rejected by browser security"; break;
    default: result = "failed before a usable credential response";
  }
  return `Passkey ${operation} ${result}.`;
}
async function nativePrompt(operation, action) {
  try { return await duringPage(action); }
  catch (error) {
    if (error.name === "PageChangedError") throw error;
    let reason;
    switch (error.name) {
      case "NotAllowedError": reason = "not_completed"; break;
      case "AbortError": reason = "aborted"; break;
      case "TimeoutError": reason = "timed_out"; break;
      case "SecurityError": reason = "security"; break;
      default: reason = "failed";
    }
    // Retain only a fixed operation/category, never provider messages or causes.
    throw Object.assign(new Error("Passkey prompt failed"), {name: "PasskeyPromptError", operation, reason});
  }
}
export function accountId(input) {
  const id = input.value.trim();
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) {
    throw new Error("Invalid account identifier");
  }
  return id;
}
export async function createKey(options) {
  if (typeof globalThis.PublicKeyCredential?.parseCreationOptionsFromJSON !== "function") throw Object.assign(new Error("Unsupported browser"), {name: "UnsupportedPasskeyClient"});
  const credential = await nativePrompt("creation", signal => navigator.credentials.create({
    publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options.publicKey), signal
  }));
  if (!credential || typeof credential.toJSON !== "function") throw new Error("No credential");
  return credential.toJSON();
}
export async function assertKey(options) {
  if (typeof globalThis.PublicKeyCredential?.parseRequestOptionsFromJSON !== "function") throw Object.assign(new Error("Unsupported browser"), {name: "UnsupportedPasskeyClient"});
  const credential = await nativePrompt("verification", signal => navigator.credentials.get({
    publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options.publicKey), signal
  }));
  if (!credential || typeof credential.toJSON !== "function") throw new Error("No assertion");
  return credential.toJSON();
}
