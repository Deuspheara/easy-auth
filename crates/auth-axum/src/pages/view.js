"use strict";

export const element = id => document.getElementById(id);
let lifecycle = 0;
const active = new Set();
function syncAccountButtons() {
  for (const button of document.querySelectorAll("#account button")) button.disabled = active.size > 0;
}
window.addEventListener("pagehide", () => {
  lifecycle += 1;
  for (const release of [...active]) release();
});
let notificationTimer;
export function announce(text) {
  clearTimeout(notificationTimer);
  delete element("status").dataset.transient;
  element("status").textContent = text;
}
export function notify(text) {
  announce(text);
  element("status").dataset.transient = "true";
  notificationTimer = setTimeout(() => announce(""), 8000);
}
export function errorMessage(error, signIn = false) {
  if (error.name === "PageChangedError") return "The page or account changed. Check your account before trying again; no action is confirmed here.";
  if (error.name === "UnsupportedPasskeyClient") return "This browser cannot use this passkey client. Use a supported browser with your existing key.";
  if (error.name === "PasskeyPromptError") return "The passkey prompt did not complete. No sign-in or account change is confirmed. Check your account before trying again.";
  if (error.status === 401) return signIn ? "Sign-in was not confirmed. Check your details or request a fresh link in this browser. An existing session may need explicit sign-out first." : "This action needs a fresh sign-in with the method your account requires. Sign out explicitly before choosing another account.";
  if (error.status === 429) return "Too many attempts. Wait before trying again.";
  if (error.status === 400) return "The request was not accepted. Check the fields, use a fresh link or refresh account details before trying again.";
  return "The action was not confirmed. Refresh your account before trying again. Do not repeat a passkey or provider completion automatically.";
}

export async function run(container, action, pending = "Working…") {
  if (container.getAttribute("aria-busy") === "true") return;
  const buttons = container.matches("button") ? [container] : [...container.querySelectorAll("button")];
  const disabled = buttons.map(button => button.disabled);
  const focused = document.activeElement;
  const stamp = lifecycle;
  const release = () => {
    if (!active.delete(release)) return;
    container.removeAttribute("aria-busy");
    buttons.forEach((button, index) => { if (button.isConnected) button.disabled = disabled[index]; });
    syncAccountButtons();
    if (stamp === lifecycle && document.activeElement === document.body && focused?.isConnected && focused.getClientRects().length) focused.focus();
  };
  active.add(release);
  container.setAttribute("aria-busy", "true");
  buttons.forEach(button => { button.disabled = true; });
  syncAccountButtons();
  announce(pending);
  try { await action(); }
  catch (error) {
    if (stamp === lifecycle) announce(errorMessage(error, ["email-form", "password-form", "passkey-form", "account-passkey-form", "signup-form"].includes(container.id)));
  }
  finally { release(); }
}

export function submit(id, action, pending) {
  const form = element(id);
  form.addEventListener("submit", event => {
    event.preventDefault();
    void run(form, action, pending);
  });
}

export function actionButton(label, action, danger = false) {
  const button = document.createElement("button");
  button.type = "button";
  button.disabled = active.size > 0;
  button.className = danger ? "danger" : "secondary";
  button.textContent = label;
  button.addEventListener("click", () => { void run(button, action); });
  return button;
}

export function paragraph(text) {
  const node = document.createElement("p");
  node.textContent = text;
  return node;
}

export function activity(value) {
  const age = Math.max(0, Date.now() - value);
  if (!Number.isFinite(age)) return "unavailable";
  if (age < 60000) return "just now";
  const minutes = Math.floor(age / 60000);
  if (minutes < 60) return minutes + (minutes === 1 ? " minute ago" : " minutes ago");
  return new Date(value).toLocaleDateString(undefined, {month: "short", day: "numeric", year: "numeric"});
}

export function date(value) {
  const date = new Date(value);
  return Number.isFinite(date.getTime()) ? date.toLocaleString() : "Unavailable";
}

export function confirmAction(title, description, acceptLabel = "Confirm") {
  const dialog = element("confirmation");
  if (dialog.open || typeof dialog.showModal !== "function") return Promise.resolve(false);
  element("confirmation-accept").textContent = acceptLabel;
  element("confirmation-title").textContent = title;
  element("confirmation-description").textContent = description;
  dialog.returnValue = "cancel";
  return new Promise(resolve => {
    dialog.addEventListener("close", () => resolve(dialog.returnValue === "confirm"), {once: true});
    dialog.showModal();
  });
}

export function clearSecrets() {
  document.querySelectorAll('input[type="password"]').forEach(input => { input.value = ""; });
  if (element("confirmation").open) element("confirmation").close("cancel");
}
