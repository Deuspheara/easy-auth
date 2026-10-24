"use strict";
import {element} from "/ui/view.js";

export function renderAccount(user, caps) {
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
}
