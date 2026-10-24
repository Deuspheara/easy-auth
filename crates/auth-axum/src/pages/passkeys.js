"use strict";
import {request, createKey} from "/ui/browser-operations.js";
import {element, announce, errorMessage, actionButton, paragraph, date, submit, confirmAction, run} from "/ui/view.js";
import {currentView, requireView} from "/ui/account.js";

let requireCurrent;
let refresh;

export function bindPasskeys(refreshAccount, checkAccount, caps) {
  refresh = refreshAccount;
  requireCurrent = checkAccount;
  element("refresh-passkeys").addEventListener("click", () => {
    void run(element("refresh-passkeys"), async () => {
      const loaded = await loadPasskeys(caps);
      announce(loaded ? "Passkeys loaded." : element("passkeys-state").textContent || "The account changed. Check sign-in before continuing.");
    }, "Loading passkeys…");
  });
  submit("enrollment-form", async () => {
    await requireCurrent();
    const current = currentView();
    const started = await request("/v1/passkeys/enrollment/start", {label: element("key-label").value, discoverable: true});
    const credential = await createKey(started.options);
    await requireCurrent();
    requireView(current);
    await request("/v1/passkeys/enrollment/finish", {transaction_id: started.transaction_id, credential});
    await refresh();
    announce("Passkey added. Sign in with it to prove it works before relying on it as your remaining key.");
  }, "Create your additional passkey…");
}

export async function loadPasskeys(caps) {
  if (!caps.passkeyManagement) return false;
  const current = currentView();
  element("passkeys-state").textContent = "Loading passkeys…";
  try {
    const inventory = await request("/v1/passkeys");
    await requireCurrent();
    if (!current()) return false;
    element("passkeys").replaceChildren();
    for (const key of inventory.passkeys) element("passkeys").append(keyRow(key, current));
    element("passkeys-state").textContent = inventory.passkeys.length ? "" : "No passkeys listed.";
    return true;
  } catch (error) {
    if (current()) element("passkeys-state").textContent = errorMessage(error);
    return false;
  }
}

function keyRow(key, current) {
  const row = document.createElement("li");
  const details = document.createElement("details");
  details.className = "key-details";
  const summary = document.createElement("summary");
  summary.textContent = key.label;
  details.append(summary, paragraph("Created " + date(key.created_at_ms)));
  details.append(paragraph(key.last_used_at_ms === null ? "Not yet used for sign-in" : "Last used " + date(key.last_used_at_ms)));
  const form = document.createElement("form");
  form.method = "post";
  form.action = "/v1/passkeys/rename";
  const label = document.createElement("label");
  label.textContent = "Passkey name";
  const input = document.createElement("input");
  input.value = key.label;
  input.required = true;
  input.maxLength = 256;
  input.autocomplete = "off";
  label.append(input);
  const save = actionButton("Save name", async () => {
    if (!input.reportValidity()) return;
    await requireCurrent();
    requireView(current);
    await request("/v1/passkeys/rename", {id: key.id, version: key.version, label: input.value});
    await refresh();
    announce("Passkey name updated.");
  });
  save.setAttribute("aria-label", "Save name for " + key.label);
  form.append(label, save);
  form.addEventListener("submit", event => { event.preventDefault(); form.querySelector("button").click(); });
  const remove = actionButton("Remove passkey", async () => {
    if (!await confirmAction("Remove this passkey?", "This signs out all sessions. Another passkey that has already signed in must remain. The server will refuse removal otherwise.")) {
      announce("Cancelled. No passkey removal request was sent.");
      return;
    }
    await requireCurrent();
    requireView(current);
    await request("/v1/passkeys/remove", {id: key.id, version: key.version});
    await refresh();
    announce("Passkey removed and sessions signed out. Sign in with your remaining working key.");
  }, true);
  remove.setAttribute("aria-label", "Remove " + key.label);
  details.append(form, remove);
  row.append(details);
  return row;
}
