"use strict";
import {request} from "/ui/browser-operations.js";
import {element, announce, errorMessage, actionButton, paragraph, date, run, confirmAction, submit} from "/ui/view.js";

let generation = 0;
let nextProviders = null;
let nextSessions = null;
let requireCurrent;
let refresh;

export function resetAccount() {
  generation += 1;
  nextProviders = null;
  nextSessions = null;
  for (const id of ["providers", "sessions", "passkeys"]) element(id).replaceChildren();
  for (const id of ["providers-state", "sessions-state", "passkeys-state"]) element(id).textContent = "";
  for (const id of ["more-providers", "more-sessions"]) element(id).hidden = true;
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
  if (reset) element("providers").replaceChildren();
  element("providers-state").textContent = "Loading connected providers…";
  try {
    const query = !reset && nextProviders ? "?" + new URLSearchParams({after_kind: nextProviders.kind, after_id: nextProviders.id}) : "";
    const page = await request("/v1/account/providers" + query);
    await requireCurrent();
    if (!current()) return;
    for (const provider of page.providers) {
      const row = document.createElement("li");
      row.append(paragraph(provider.kind === "saml" ? "SAML provider" : "OpenID Connect provider"), paragraph(provider.issuer));
      element("providers").append(row);
    }
    nextProviders = page.next;
    element("more-providers").hidden = !nextProviders;
    element("providers-state").textContent = element("providers").children.length ? "" : "No connected providers.";
  } catch (error) {
    if (current()) element("providers-state").textContent = errorMessage(error);
  }
}

export async function loadSessions(reset = true) {
  const current = currentView();
  if (reset) element("sessions").replaceChildren();
  element("sessions-state").textContent = "Loading active sessions…";
  try {
    const query = !reset && nextSessions ? "?" + new URLSearchParams({after: nextSessions}) : "";
    const page = await request("/v1/sessions" + query);
    await requireCurrent();
    if (!current()) return;
    for (const session of page.sessions) {
      const row = document.createElement("li");
      const details = document.createElement("div");
      details.className = "session-details";
      details.append(paragraph(session.current ? "This browser" : "Another active session"));
      details.append(paragraph("Created " + date(session.created_at_ms) + " · Last seen " + date(session.last_seen_at_ms)));
      row.append(details);
      row.append(actionButton(session.current ? "Sign out this session" : "Sign out session", async () => {
        await requireCurrent();
        requireView(current);
        await request("/v1/sessions/revoke", {id: session.id});
        await refresh();
        announce("Session sign-out request completed. The refreshed list shows currently active sessions.");
      }));
      element("sessions").append(row);
    }
    nextSessions = page.next;
    element("more-sessions").hidden = !nextSessions;
    element("sessions-state").textContent = element("sessions").children.length ? "" : "No active sessions listed.";
  } catch (error) {
    if (current()) element("sessions-state").textContent = errorMessage(error);
  }
}
