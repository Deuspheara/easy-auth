"use strict";

const statusNode = document.getElementById("status");
let context = null;
const visible = node => node?.isConnected && !node.closest("[hidden]");
function fallback() {
  return document.querySelector('#account:not([hidden]) [data-account-panel]:not([hidden])') ||
    document.querySelector('[data-auth-screen]:not([hidden])') || document.querySelector('.recovery-step:not([hidden])') || document.querySelector("main");
}
export function locateFeedback(node) {
  const status = statusNode;
  if (!status) return;
  context = node;
  const target = visible(node) ? node : fallback();
  if (!target) return;
  const inventory = target.closest(".items");
  if (inventory) { inventory.before(status); status.classList.add("operation-feedback"); return; }
  if (target.contains(status) && visible(status)) return;
  if (target.matches("button, a")) (target.closest(".button-group") || target).before(status);
  else {
    const action = target.querySelector(':scope > button, :scope > .actions, :scope > p:has(> button), :scope > fieldset > button, :scope > fieldset > p:has(> button)');
    if (action) action.before(status); else target.append(status);
  }
  status.classList.add("operation-feedback");
}
export function feedback(text, error = false) {
  const status = statusNode;
  locateFeedback(visible(context) ? context : null);
  if (!status) return;
  if (error) status.dataset.variant = "destructive";
  else delete status.dataset.variant;
  status.textContent = text;
}
export function clearFeedback() {
  context = null;
  const status = statusNode;
  if (status) { status.textContent = ""; delete status.dataset.variant; }
  for (const node of document.querySelectorAll('[aria-invalid="true"]')) clearFieldError(node);
}
export function clearFieldError(input) {
  input.removeAttribute("aria-invalid");
  input.closest(".field")?.removeAttribute("data-invalid");
  const error = document.getElementById(input.id + "-error");
  if (error) {
    const descriptions = (input.getAttribute("aria-describedby") || "").split(" ").filter(id => id && id !== error.id);
    if (descriptions.length) input.setAttribute("aria-describedby", descriptions.join(" "));
    else input.removeAttribute("aria-describedby");
    error.remove();
  }
}
export function fieldError(input, text) {
  clearFieldError(input);
  const error = document.createElement("p");
  error.id = input.id + "-error";
  error.className = "field-error";
  error.textContent = text;
  input.setAttribute("aria-invalid", "true");
  input.closest(".field")?.setAttribute("data-invalid", "");
  input.setAttribute("aria-describedby", [input.getAttribute("aria-describedby"), error.id].filter(Boolean).join(" "));
  (input.closest(".field") || input.parentElement).append(error);
}
function validationText(input) {
  const label = input.labels?.[0]?.textContent.trim() || "this value";
  if (input.validity.valueMissing) return input.type === "checkbox" ? "Confirm this acknowledgement to continue." : `Enter ${label.toLocaleLowerCase()}.`;
  if (input.validity.typeMismatch && input.type === "email") return "Enter an email address in the format name@example.com.";
  if (input.validity.patternMismatch) return input.id.includes("confirmation") ? "Enter the exact confirmation phrase." : "Enter the retained account ID in UUID format.";
  if (input.validity.tooShort) return `Enter at least ${input.minLength} characters.`;
  return input.validationMessage;
}
let focusing = false;
document.addEventListener("invalid", event => {
  const input = event.target;
  event.preventDefault();
  fieldError(input, validationText(input));
  if (!focusing) {
    focusing = true;
    input.focus();
    queueMicrotask(() => { focusing = false; });
  }
}, true);
document.addEventListener("input", event => {
  if (event.target.hasAttribute("aria-invalid")) clearFieldError(event.target);
});
