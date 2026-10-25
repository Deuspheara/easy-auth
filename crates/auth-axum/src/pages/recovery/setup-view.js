"use strict";
import {step, focusStep} from "/ui/recovery-view.js";
import {clearFeedback} from "/ui/feedback.js";
import {request} from "/ui/browser-operations.js";
import {createSettingsSearch, settingsDestinations} from "/ui/settings-search.js";

const summaries = ["Verify a working passkey to continue.", "Working passkey verified. Prepare a code to save offline.", "Code prepared, not active. Save and confirm your offline copy.", "Saved code confirmed by the server."];
const titles = ["Verify access", "Prepare your recovery code", "Save your recovery code", "Recovery code saved"];
const labels = ["Verify access", "Ready to prepare", "Awaiting confirmation", "Confirmed"];
let current = 0;
export function showSetupStep(index, focus = true, verified = true) {
  clearFeedback();
  current = index;
  document.querySelector("main > h1").textContent = titles[index];
  step(index, index === 1 && !verified ? "Current session selected. Preparing a code still requires fresh passkey access checked by the server." : summaries[index]);
  for (const node of document.querySelectorAll("[data-setup-step]")) node.hidden = Number(node.dataset.setupStep) !== index;
  document.getElementById("setup-state").textContent = index === 1 && !verified ? "Session selected" : labels[index];
  if (focus) focusStep(document.querySelector(`[data-setup-step="${index}"]`));
}
export function resetPreparedStep() {
  if (current === 2) showSetupStep(1, false);
}
const search = createSettingsSearch(document.querySelector("main"), id => {
  if (id === "recovery") { document.querySelector("h1").focus(); search.clear(); return; }
  location.assign("/?setting=" + encodeURIComponent(id));
});
let searchRevision = 0;
export async function updateSetupSearch(user) {
  const revision = ++searchRevision;
  if (!user) { search.update([]); return; }
  try {
    const response = await fetch("/", {credentials: "same-origin", cache: "no-store"});
    if (!response.ok) return;
    const document = new DOMParser().parseFromString(await response.text(), "text/html");
    const caps = JSON.parse(document.getElementById("capabilities").value);
    if (revision === searchRevision) search.update(settingsDestinations(user, caps));
  } catch { if (revision === searchRevision) search.update([]); }
}
window.addEventListener("pagehide", () => { searchRevision += 1; search.update([]); showSetupStep(0, false); });
window.addEventListener("pageshow", event => {
  if (event.persisted) request("/v1/session").then(updateSetupSearch).catch(() => updateSetupSearch(null));
});
showSetupStep(0, false);
