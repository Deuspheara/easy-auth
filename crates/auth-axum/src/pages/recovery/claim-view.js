"use strict";
import {step, focusStep} from "/ui/recovery-view.js";
const element = id => document.getElementById(id);
let previous = null;
export function renderClaim(claim, busy = false, completed = false) {
  element("claim").hidden = !claim;
  element("claim-entry").hidden = Boolean(claim) || completed;
  element("recovery-complete").hidden = !completed;
  element("replace-form").hidden = !claim?.ready;
  element("replace").disabled = busy || !claim?.ready;
  const index = completed ? 3 : claim ? (claim.ready ? 2 : 1) : 0;
  if (previous !== index) {
    document.querySelector("main > h1").textContent = ["Recover your account", "Your request is waiting", "Install your replacement passkey", "Recovery complete"][index];
    step(index, ["Enter your retained account ID to start or resume.", "Request reserved. Keep this browser and check status manually.", "Server reports eligibility. Create and verify your replacement key.", "Replacement confirmed by the server."][index]);
    if (previous !== null) focusStep(completed ? element("recovery-complete") : claim ? element("claim") : element("start-form"));
    previous = index;
  }
  if (!claim) return;
  const date = value => value == null ? "Not available" : new Date(value).toLocaleString();
  element("claim-owner").textContent = claim.account_id;
  element("claim-state").textContent = claim.ready ? "Eligible for replacement" : "Waiting";
  element("claim-earliest").textContent = claim.not_before_ms === null ? "Waiting for notification acceptance" : date(claim.not_before_ms);
  element("claim-expiry").textContent = date(claim.expires_at_ms);
  element("claim-notification").textContent = claim.notification_required ? "Verified-contact notice required; acceptance is not proof of reading." : "No independent email alert.";
  element("timing").textContent = `Expires: ${date(claim.expires_at_ms)}. ${claim.ready ? "Server reports eligibility; every replacement step still rechecks authority." : "Not eligible yet."}`;
  element("notification").textContent = element("claim-notification").textContent;
}
