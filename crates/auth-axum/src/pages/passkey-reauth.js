"use strict";
import {request, assertKey} from "/ui/browser-operations.js";
import {confirmAction} from "/ui/view.js";
import {currentView, requireView} from "/ui/account.js";

// The API remains authoritative about freshness. Never retry a credential finish.
// Replacing this browser's session is explicit; other sessions are not revoked.
export async function verifyPasskey(refresh, signedOut, requireCurrent) {
  const user = await requireCurrent();
  const current = currentView();
  if (!await confirmAction("Verify to manage passkeys?", "For your security, this browser will be signed out before your device asks for this account’s passkey. Other sessions stay signed in. Cancel to keep your current sign-in.", "Verify with passkey")) return false;
  await requireCurrent();
  requireView(current);
  await request("/v1/logout", {});
  signedOut();
  const started = await request("/v1/passkeys/authentication/start", {mode: "account_bound", account_id: user.id});
  const credential = await assertKey(started.options);
  await request("/v1/passkeys/authentication/finish", {transaction_id: started.transaction_id, credential});
  const verified = await refresh();
  if (!verified || verified.id !== user.id) throw Object.assign(new Error("Account changed"), {name: "PageChangedError"});
  return true;
}
