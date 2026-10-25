"use strict";
import {providerRow, sessionRow} from "/ui/inventory-rows.js";
import {updateMethodsVisibility} from "/ui/account-view.js";
import {request} from "/ui/browser-operations.js";
import {cancelPresentation, element, announce, notify, errorMessage, paragraph, date, run, confirmAction, submit} from "/ui/view.js";

let generation = 0;
let nextProviders = null;
let nextSessions = null;
let requireCurrent;
let refresh;

export function resetAccount() {
  cancelPresentation();
  generation += 1;
  nextProviders = null;
  nextSessions = null;
  for (const id of ["providers", "sessions", "current-session", "passkeys", "session-diagnostics", "provider-diagnostics"]) element(id).replaceChildren();
  for (const id of ["providers-state", "sessions-state", "passkeys-state"]) element(id).textContent = "";
  element("passkeys-summary").textContent = "View and manage registered passkeys";
  element("retry-passkeys").hidden = false;
  element("retry-passkeys").textContent = "Verify access";
  element("passkeys-state").textContent = "Verify access to view your registered passkeys.";
  for (const id of ["more-providers", "more-sessions", "retry-providers", "refresh-account", "retry-sessions"]) element(id).hidden = true;
}

export function currentView() {
  const stamp = generation;
  return () => stamp === generation;
}

export function requireView(current) {
  if (!current()) throw Object.assign(new Error("View changed"), {name: "PageChangedError"});
}

export function bindAccount(refreshAccount, checkAccount) {
  refresh = refreshAccount;
  requireCurrent = checkAccount;
  bindAccountRequests();
  for (const id of ["manage-sessions", "retry-sessions"]) element(id).addEventListener("click", () => {
    void run(element(id), async () => { await loadSessions(); announce(element("sessions-state").textContent); });
  });
  element("retry-providers").addEventListener("click", () => { void run(element("retry-providers"), () => loadProviders()); });
  element("more-providers").addEventListener("click", () => { void run(element("more-providers"), () => loadProviders(false)); });
  element("more-sessions").addEventListener("click", () => { void run(element("more-sessions"), () => loadSessions(false)); });
  element("revoke-all").addEventListener("click", () => {
    void run(element("revoke-all"), async () => {
      if (!await confirmAction("Sign out all sessions?", "Every current session, including this browser, will be signed out. Outstanding sign-in and account-action proofs will be cancelled.")) {
        announce("Cancelled. No sign-out request was sent.");
        return;
      }
      await requireCurrent();
      await request("/v1/sessions/revoke-all", {});
      await refresh();
      announce("All sessions were signed out. Sign in again when you are ready.");
    });
  });
}

function bindAccountRequests() {
  submit("email-change-form", async () => {
    await requireCurrent();
    await request("/v1/account/email/start", {email: element("new-email").value});
    announce("Check both email inboxes. Confirm both links in this browser to change your address.");
  }, "Requesting email confirmation…");
  submit("attachment-start-form", async () => {
    await requireCurrent();
    await request("/v1/account/email/attachment/start", {email: element("contact-email").value});
    announce("Check your contact email and confirm its link in this browser. Your passkey is still required to sign in.");
  }, "Requesting contact confirmation…");
  submit("deletion-start-form", async () => {
    await requireCurrent();
    await request("/v1/account/delete/start", {confirmation: element("delete-confirmation").value});
    element("delete-confirmation").value = "";
    announce("Deletion was requested. Open the confirmation email in this browser and confirm only if you intend to delete this account.");
  }, "Requesting deletion confirmation…");
}

export async function loadProviders(reset = true) {
  const current = currentView();
  if (reset) { element("providers").replaceChildren(); element("provider-diagnostics").replaceChildren(); }
  element("providers-card").hidden = false;
  element("retry-providers").hidden = true;
  element("providers-card").removeAttribute("data-loaded");
  updateMethodsVisibility();
  element("providers-state").textContent = "Loading connected providers…";
  try {
    const query = !reset && nextProviders ? "?" + new URLSearchParams({after_kind: nextProviders.kind, after_id: nextProviders.id}) : "";
    const page = await request("/v1/account/providers" + query);
    await requireCurrent();
    if (!current()) return;
    for (const provider of page.providers) {
      element("providers").append(providerRow(provider));
      const diagnostic = document.createElement("li");
      diagnostic.append(paragraph(provider.kind), paragraph(provider.issuer));
      element("provider-diagnostics").append(diagnostic);
    }
    nextProviders = page.next;
    element("more-providers").hidden = !nextProviders;
    element("providers-state").textContent = "";
    element("providers-card").hidden = element("providers").children.length === 0;
    element("providers-card").dataset.loaded = "true";
    updateMethodsVisibility();
  } catch (error) {
    if (current()) { element("providers-state").textContent = errorMessage(error); element("retry-providers").hidden = false; }
  }
}

export async function loadSessions(reset = true) {
  const current = currentView();
  if (reset) { for (const id of ["sessions", "current-session", "session-diagnostics"]) element(id).replaceChildren(); }
  element("refresh-account").hidden = element("retry-sessions").hidden = true;
  element("session-overview-state").textContent = "Checking sessions…";
  element("sessions-state").textContent = "Loading active sessions…";
  try {
    const query = !reset && nextSessions ? "?" + new URLSearchParams({after: nextSessions}) : "";
    const page = await request("/v1/sessions" + query);
    await requireCurrent();
    if (!current()) return;
    for (const session of page.sessions) {
      const row = sessionRow(session, async () => {
        await requireCurrent();
        requireView(current);
        await request("/v1/sessions/revoke", {id: session.id});
        await refresh();
        notify("Session signed out.");
      });
      element("sessions").append(row);
      if (session.current) element("current-session").replaceChildren(sessionRow(session, () => {}));
      const diagnostic = document.createElement("li");
      diagnostic.append(paragraph(session.current ? "This browser" : "Another session"), paragraph("Created " + date(session.created_at_ms) + " · Last seen " + date(session.last_seen_at_ms)));
      element("session-diagnostics").append(diagnostic);
    }
    element("session-overview-state").textContent = element("current-session").children.length ? "" : "Open session management for more details.";
    nextSessions = page.next;
    element("more-sessions").hidden = !nextSessions;
    element("sessions-state").textContent = element("sessions").children.length ? "" : "No active sessions listed.";
  } catch (error) {
    if (current()) { element("sessions-state").textContent = errorMessage(error); element("session-overview-state").textContent = errorMessage(error); element("refresh-account").hidden = element("retry-sessions").hidden = false; }
  }
}
