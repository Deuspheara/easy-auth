"use strict";
import {feedback, locateFeedback, clearFeedback, fieldError} from "/ui/feedback.js";

import {accountId} from "/ui/browser-operations.js";
export function recoveryAccountId(input) {
  try { return accountId(input); }
  catch (error) { fieldError(input, "Enter the retained account ID in UUID format."); input.focus(); throw error; }
}

export function step(index, summary) {
  for (const node of document.querySelectorAll("[data-step]")) {
    node.classList.toggle("completed", Number(node.dataset.step) < index);
    if (Number(node.dataset.step) === index) node.setAttribute("aria-current", "step");
    else node.removeAttribute("aria-current");
  }
  document.getElementById("step-summary").textContent = summary;
  closeHelp();
}
export function closeHelp() {
  for (const node of document.querySelectorAll('.recovery-help > button[aria-expanded="true"]')) node.click();
}
export function recoveryOperation(failure, render = () => {}) {
  let busy = false;
  let generation = 0;
  let interrupted = false;
  window.addEventListener("pagehide", () => { interrupted = busy; generation += 1; closeHelp(); clearFeedback(); });
  window.addEventListener("pageshow", event => {
    if (event.persisted) {
      render();
      if (interrupted) feedback(failure({name: "PageChangedError"}), true);
      interrupted = false;
    }
  });
  return async (container, action) => {
    if (busy) return;
    busy = true;
    const stamp = generation;
    const controls = [...document.querySelectorAll('button, input')].filter(node => !node.closest('.recovery-help, .settings-search'));
    const disabled = controls.map(node => node.disabled);
    locateFeedback(container);
    container.setAttribute("aria-busy", "true");
    feedback("Working…");
    controls.forEach(node => { node.disabled = true; });
    try { await action(); }
    catch (error) { if (stamp === generation) feedback(failure(error), true); }
    finally {
      busy = false;
      container.removeAttribute("aria-busy");
      controls.forEach((node, index) => { node.disabled = disabled[index]; });
      if (stamp === generation) {
        render();
        const invalid = document.querySelector('[aria-invalid="true"]');
        if (invalid && (document.activeElement === document.body || container.contains(document.activeElement))) invalid.focus();
      }
    }
  };
}
export function focusStep(node) {
  const heading = node.querySelector("h2, legend");
  if (heading) { heading.tabIndex = -1; heading.focus(); }
}
export {feedback};
