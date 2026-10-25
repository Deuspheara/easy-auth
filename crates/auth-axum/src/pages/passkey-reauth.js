"use strict";
import {request} from "/ui/browser-operations.js";
import {confirmAction, element, announce} from "/ui/view.js";
import {showAuthScreen} from "/ui/auth-screens.js";
import {currentView, requireView} from "/ui/account.js";

let verificationOwner = null;
window.addEventListener("pagehide", () => { verificationOwner = null; });

// Reuse ordinary account-bound sign-in from a fresh, explicit button click.
// No native prompt is chained to closing a dialog or to signing out.
export async function verifyPasskey(signedOut, requireCurrent, caps) {
  const user = await requireCurrent();
  const current = currentView();
  if (!await confirmAction("Verify to manage passkeys?", "This browser will be signed out. Then choose Continue with your passkey to verify this account. Other sessions stay signed in. Cancel to keep your current sign-in.", "Sign out and continue")) return false;
  await requireCurrent();
  requireView(current);
  await request("/v1/logout", {});
  signedOut();
  showAuthScreen(caps, "account-passkey");
  verificationOwner = user.id;
  element("passkey-account").value = user.id;
  element("heading").textContent = "Verify your passkey";
  element("intro").textContent = "Continue with a passkey for the account you were managing.";
  announce("This browser is signed out. Choose Continue with your passkey to open your device prompt.");
  element("account-passkey-form").querySelector('button[type="submit"]').focus();
  return "pending";
}

// A loaded session only selects presentation. The inventory endpoint still
// checks the real authentication method/freshness before revealing credentials.
export function resumePasskeyManagement(user) {
  if (!verificationOwner) return false;
  const expected = verificationOwner;
  verificationOwner = null;
  if (user.id !== expected) throw Object.assign(new Error("Account changed"), {name: "PageChangedError"});
  return true;
}
