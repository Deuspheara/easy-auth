"use strict";
import {request} from "/ui/browser-operations.js";
import {element, announce, notify, run, clearSecrets, errorMessage} from "/ui/view.js";
import {showAuthScreen} from "/ui/auth-screens.js";
import {bindSignIn, finishEmail} from "/ui/signin.js";
import {bindAccount, resetAccount, loadProviders, loadSessions} from "/ui/account.js";
import {verifyPasskey} from "/ui/passkey-reauth.js";
import {renderAccount, bindAccountViews, resetAccountPanels, showAccountPanel} from "/ui/account-view.js";
import {bindPasskeys, loadPasskeys} from "/ui/passkeys.js";

const caps = JSON.parse(element("capabilities").value);
let initialView = new URLSearchParams(location.search).get("view");
if (initialView === "inbox") initialView = "email";
let revision = 0;
let owner = null;

function signedOut() {
  announce("");
  owner = null;
  revision += 1;
  resetAccount();
  resetAccountPanels();
  clearSecrets();
  element("account").hidden = true;
  element("sign-in").hidden = false;
  element("logout").hidden = true;
  element("clear-session").hidden = false;
  element("check-session").hidden = true;
  document.body.dataset.account = "signed-out";
  element("identity-name").textContent = "";
  element("identity-email").textContent = "";
  element("avatar").textContent = "";
  element("details-name").textContent = "";
  element("details-email").textContent = "";
  element("header-context").hidden = element("account-back").hidden = true;
  element("account-id").textContent = "";
  showAuthScreen(caps, initialView);
  initialView = "email";
}

async function refresh() {
  const stamp = ++revision;
  const previousOwner = owner;
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
  if (previousOwner && user.id !== previousOwner) { resetAccountPanels(); clearSecrets(); }
  owner = user.id;
  renderAccount(user, caps);
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
  if (user) { showAccountPanel("passkeys"); await loadPasskeys(caps); }
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
  return user;
}

for (const node of document.querySelectorAll("[data-cap]")) node.hidden = caps[node.dataset.cap] !== true;
element("other-methods").hidden = !["passkeySignin", "google", "oidc", "saml"].some(name => caps[name] === true);
bindAccountViews();
bindAccount(refreshForAction, requireCurrent);
bindPasskeys(refreshKeys, requireCurrent, caps, () => verifyPasskey(refresh, signedOut, requireCurrent));
bindSignIn(refresh, requireCurrent, caps);
for (const id of ["refresh-account", "check-session"]) {
  element(id).addEventListener("click", () => {
    void run(element(id), async () => {
      if (await refreshForAction()) notify("Account updated.");
      else announce("This browser is signed out.");
    }, "Checking sign-in…");
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
  const label = dark ? "Use light theme" : "Use dark theme";
  element("theme").setAttribute("aria-label", label);
  element("theme").title = label;
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
let refreshingOnReturn = false;
async function refreshOnReturn() {
  if (!owner || document.visibilityState !== "visible" || refreshingOnReturn || document.querySelector('[aria-busy="true"]')) return;
  refreshingOnReturn = true;
  try { await refresh(); } catch (error) { announce(errorMessage(error)); }
  finally { refreshingOnReturn = false; }
}
window.addEventListener("focus", refreshOnReturn);
document.addEventListener("visibilitychange", refreshOnReturn);
window.addEventListener("hashchange", () => {
  if (new URLSearchParams(location.hash.slice(1)).has("token")) void finishEmail(refresh).catch(error => announce(errorMessage(error)));
});
void finishEmail(refresh).catch(error => announce(errorMessage(error)));
