"use strict";
import {request} from "/ui/browser-operations.js";
import {element, announce, run, clearSecrets, errorMessage} from "/ui/view.js";
import {bindSignIn, finishEmail} from "/ui/signin.js";
import {bindAccount, resetAccount, loadProviders, loadSessions} from "/ui/account.js";
import {bindPasskeys, loadPasskeys} from "/ui/passkeys.js";

const caps = JSON.parse(element("capabilities").value);
let revision = 0;
let owner = null;

function signedOut() {
  owner = null;
  revision += 1;
  resetAccount();
  clearSecrets();
  element("account").hidden = true;
  element("sign-in").hidden = false;
  element("logout").hidden = true;
  element("clear-session").hidden = false;
  element("check-session").hidden = true;
  document.body.dataset.account = "signed-out";
  element("identity").textContent = "";
  element("account-id").textContent = "";
  element("heading").textContent = "Sign in to easy-auth";
  element("intro").textContent = "Use a sign-in method available for your account.";
}

async function refresh() {
  const stamp = ++revision;
  owner = null;
  resetAccount();
  element("account").hidden = true;
  let user;
  try { user = await request("/v1/session"); }
  catch (error) {
    if (stamp !== revision) return null;
    signedOut();
    if (error.status !== 401) throw error;
    return null;
  }
  if (stamp !== revision) return null;
  owner = user.id;
  element("sign-in").hidden = true;
  element("account").hidden = false;
  element("logout").hidden = false;
  element("clear-session").hidden = true;
  element("check-session").hidden = false;
  document.body.dataset.account = "signed-in";
  element("heading").textContent = "Account";
  element("intro").textContent = "Manage your sign-in methods and active sessions.";
  element("identity").textContent = [user.display_name, user.email].filter(Boolean).join(" · ") || "Signed-in account";
  element("account-id").textContent = user.id;
  const mailbox = user.authentication_policy === "mailbox";
  const passkeysAllowed = mailbox || user.authentication_policy === "passkey_required";
  element("mailbox-actions").hidden = !mailbox;
  element("password-enrollment").hidden = !(mailbox && caps.passwords);
  element("attach-action").hidden = !(user.authentication_policy === "passkey_required" && !user.email && caps.emailAttachment);
  element("provider-deletion").hidden = user.authentication_policy !== "provider_required" || ![caps.oidcDeletion, caps.googleDeletion, caps.samlDeletion].some(Boolean);
  element("passkeys-card").hidden = !(passkeysAllowed && (caps.passkeyEnrollment || caps.passkeyManagement || caps.recoverySetup));
  if (caps.passkeyManagement) element("passkeys-state").textContent = "After a fresh passkey sign-in, choose Load passkeys to manage your keys.";
  await Promise.all([loadProviders(), loadSessions()]);
  return stamp === revision ? user : null;
}

function changed() { return Object.assign(new Error("Account changed"), {name: "PageChangedError"}); }
async function refreshForAction() {
  const user = await refresh();
  element("heading").focus();
  return user;
}
async function refreshKeys() {
  const user = await refreshForAction();
  if (user) await loadPasskeys(caps);
  return user;
}
async function requireCurrent() {
  const stamp = revision;
  const expected = owner;
  if (!expected) throw changed();
  let user;
  try { user = await request("/v1/session"); }
  catch (error) {
    if (stamp === revision && error.status === 401) signedOut();
    throw error;
  }
  if (stamp !== revision) throw changed();
  if (user.id !== expected) {
    signedOut();
    announce("The signed-in account changed. Check sign-in before continuing.");
    throw changed();
  }
}

for (const node of document.querySelectorAll("[data-cap]")) node.hidden = caps[node.dataset.cap] !== true;
element("other-methods").hidden = !["passkeySignin", "passkeySignup", "google", "oidc", "saml", "recovery"].some(name => caps[name] === true);
bindAccount(refreshForAction, requireCurrent);
bindPasskeys(refreshKeys, requireCurrent, caps);
bindSignIn(refresh, requireCurrent);
for (const id of ["refresh-account", "check-session"]) {
  element(id).addEventListener("click", () => {
    void run(element(id), async () => announce(await refreshForAction() ? "Account refreshed." : "This browser is signed out."), "Checking sign-in…");
  });
}
for (const id of ["logout", "clear-session"]) {
  element(id).addEventListener("click", () => {
    void run(element(id), async () => {
      await request("/v1/logout", {});
      signedOut();
      element("heading").focus();
      announce("Signed out in this browser.");
    }, "Signing out…");
  });
}
const colorPreference = matchMedia("(prefers-color-scheme: dark)");
function themeLabel() {
  const dark = document.documentElement.dataset.theme === "dark" || (!document.documentElement.dataset.theme && colorPreference.matches);
  element("theme").textContent = dark ? "Use light theme" : "Use dark theme";
  return dark;
}
element("theme").addEventListener("click", () => {
  document.documentElement.dataset.theme = themeLabel() ? "light" : "dark";
  themeLabel();
});
themeLabel();
colorPreference.addEventListener("change", themeLabel);
window.addEventListener("pagehide", signedOut);
window.addEventListener("pageshow", event => {
  if (event.persisted) {
    clearSecrets();
    void refresh().catch(error => announce(errorMessage(error)));
  }
});
window.addEventListener("hashchange", () => {
  if (new URLSearchParams(location.hash.slice(1)).has("token")) void finishEmail(refresh).catch(error => announce(errorMessage(error)));
});
void finishEmail(refresh).catch(error => announce(errorMessage(error)));
