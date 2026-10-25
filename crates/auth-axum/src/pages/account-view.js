"use strict";
import {clearFeedback} from "/ui/feedback.js";
import {cancelPresentation, present, element, clearSecrets} from "/ui/view.js";

let panel = "overview";
let allowed = new Set(["overview", "details", "sessions"]);
const descriptions = {overview: "Your profile and security settings.", sessions: "Review and sign out active sessions.", details: "Your name and contact information.", passkeys: "Add, rename or remove your passkeys.", password: "Manage password sign-in for this account."};
const titles = {overview: "Account", sessions: "Sessions", details: "Profile", passkeys: "Passkeys", password: "Password sign-in"};

export function showAccountPanel(requested, focus = true) {
  cancelPresentation();
  clearFeedback();
  panel = allowed.has(requested) ? requested : "overview";
  for (const node of document.querySelectorAll("[data-account-panel]")) node.hidden = node.dataset.accountPanel !== panel;
  element("account-back").hidden = panel === "overview";
  element("heading").textContent = titles[panel];
  element("intro").textContent = descriptions[panel];
  if (focus) { element("heading").focus(); present(document.querySelector(`[data-account-panel="${panel}"]`)); }
}

export function resetAccountPanels() {
  panel = "overview";
  for (const form of document.querySelectorAll("#account form")) form.reset();
  for (const form of document.querySelectorAll('#account form:not(#enroll-password-form)')) form.hidden = true;
  for (const button of document.querySelectorAll("[data-reveal]")) button.setAttribute("aria-expanded", "false");
  element("developer-details").open = false;
}

export function bindAccountViews() {
  for (const button of document.querySelectorAll("[data-open-account]")) button.addEventListener("click", () => {
    if (document.querySelector('[aria-busy="true"]')) return;
    clearSecrets();
    showAccountPanel(button.dataset.openAccount);
  });
  for (const button of document.querySelectorAll("[data-reveal]")) {
    button.setAttribute("aria-controls", button.dataset.reveal);
    button.setAttribute("aria-expanded", "false");
    button.addEventListener("click", () => {
      const form = element(button.dataset.reveal);
      form.hidden = !form.hidden;
      button.setAttribute("aria-expanded", String(!form.hidden));
      if (!form.hidden) { form.querySelector("input").focus(); present(form, true); }
    });
  }
}

export function updateMethodsVisibility() {
  element("signin-methods").hidden = ["passkeys-card", "password-entry", "recovery-card", "providers-card"].every(id => element(id).hidden);
}

export function renderAccount(user, caps) {
  element("sign-in").hidden = true;
  element("account").hidden = false;
  element("logout").hidden = false;
  element("clear-session").hidden = true;
  element("check-session").hidden = false;
  document.body.dataset.account = "signed-in";
  const name = user.display_name || "Your account";
  element("identity-name").textContent = name;
  element("identity-email").textContent = user.email || "";
  element("identity-email").hidden = !user.email;
  element("identity-email").title = user.email || "";
  element("details-name").textContent = name;
  element("details-email").textContent = user.email || "";
  element("details-email-field").hidden = !user.email;
  element("header-context").hidden = false;
  const words = (user.display_name || user.email || "A").trim().split(/\s+/);
  element("avatar").textContent = [words[0], ...(words.length > 1 ? [words.at(-1)] : [])].map(word => Array.from(word)[0]).join("").toLocaleUpperCase();
  element("account-id").textContent = user.id;
  const mailbox = user.authentication_policy === "mailbox";
  const passkeysAllowed = mailbox || user.authentication_policy === "passkey_required";
  element("mailbox-actions").hidden = element("mailbox-deletion").hidden = !mailbox;
  element("password-entry").hidden = element("password-enrollment").hidden = !(mailbox && caps.passwords);
  element("attach-action").hidden = !(user.authentication_policy === "passkey_required" && !user.email && caps.emailAttachment);
  element("provider-deletion").hidden = user.authentication_policy !== "provider_required" || ![caps.oidcDeletion, caps.googleDeletion, caps.samlDeletion].some(Boolean);
  element("account-deletion").hidden = !mailbox && element("provider-deletion").hidden;
  element("passkeys-card").hidden = !(passkeysAllowed && (caps.passkeyEnrollment || caps.passkeyManagement));
  element("enroll-passkey-entry").hidden = !(passkeysAllowed && caps.passkeyEnrollment && !caps.passkeyManagement);
  element("recovery-card").hidden = !(passkeysAllowed && caps.recoverySetup);
  allowed = new Set(["overview", "details", "sessions"]);
  if (!element("passkeys-card").hidden) allowed.add("passkeys");
  if (!element("password-entry").hidden) allowed.add("password");
  updateMethodsVisibility();
  showAccountPanel(panel, false);
}
