"use strict";
import {request} from "/ui/browser-operations.js";
import {actionButton, paragraph, activity, confirmAction, announce, notify} from "/ui/view.js";
import {requireView} from "/ui/account.js";

function renameForm(key, current, requireCurrent, refresh) {
  const form = document.createElement("form");
  form.method = "post";
  form.action = "/v1/passkeys/rename";
  form.hidden = true;
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
    notify("Passkey name updated.");
  });
  save.setAttribute("aria-label", "Save name for " + key.label);
  form.append(label, save);
  form.addEventListener("submit", event => { event.preventDefault(); save.click(); });
  return {form, edit: () => { form.hidden = !form.hidden; if (!form.hidden) input.focus(); }};
}

export function keyRow(key, current, requireCurrent, refresh) {
  const row = document.createElement("li");
  const heading = document.createElement("div");
  heading.className = "object-row";
  const icon = document.createElement("span");
  icon.className = "object-icon";
  icon.setAttribute("aria-hidden", "true");
  icon.textContent = "⚿";
  const copy = document.createElement("div");
  copy.className = "object-copy";
  const title = document.createElement("h3");
  title.textContent = key.label;
  copy.append(title, paragraph(key.last_used_at_ms === null ? "Not yet used for sign-in" : "Last used " + activity(key.last_used_at_ms)));
  const editor = renameForm(key, current, requireCurrent, refresh);
  const rename = actionButton("Rename", editor.edit);
  rename.setAttribute("aria-label", "Rename " + key.label);
  const remove = actionButton("Remove", async () => {
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
  const actions = document.createElement("div");
  actions.className = "actions";
  actions.append(rename, remove);
  heading.append(icon, copy, actions);
  row.append(heading, editor.form, paragraph("Added " + new Date(key.created_at_ms).toLocaleDateString()));
  return row;
}
