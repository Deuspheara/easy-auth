"use strict";
// Enhancement loading never sits on the request or native credential path.
let animate;
void import("/ui/motion.js").then(module => { animate = module.animate; }).catch(() => {});
const reduced = matchMedia("(prefers-reduced-motion: reduce)");
const forced = matchMedia("(forced-colors: active)");
const owned = new Map();
let generation = 0;

function release(node, entry) {
  if (owned.get(node) !== entry) return;
  owned.delete(node);
  entry.handle?.cancel();
  // These dedicated view wrappers have no application-owned inline transforms.
  // Never restore a style attribute over newer application state.
  node.style.removeProperty("opacity");
  node.style.removeProperty("transform");
}
export function cancelPresentation() {
  generation += 1;
  for (const [node, entry] of owned) release(node, entry);
}
export function present(node, supporting = false) {
  if (!animate || !node?.isConnected || node.hidden || reduced.matches || forced.matches) return;
  // Never start an effect inside an active request/native credential operation.
  if (document.querySelector('[aria-busy="true"]')) return;
  if (owned.has(node)) release(node, owned.get(node));
  const stamp = generation;
  const entry = {handle: null, completed: 0};
  owned.set(node, entry);
  try {
    entry.handle = animate(node, {
      opacity: [0.96, 1], transform: [supporting ? "translateY(2px)" : "translateY(4px)", "translateY(0px)"]
    }, {duration: supporting ? 0.12 : 0.16, ease: [0.2, 0.8, 0.2, 1], onComplete: () => {
      if (stamp !== generation || owned.get(node) !== entry) return;
      // Mini invokes completion once for each animated property.
      if (++entry.completed === 2) release(node, entry);
    }});
  } catch { release(node, entry); }
}
function committed(event) { present(event.detail.node, event.detail.supporting); }
function mountPreferences() {
  document.addEventListener("ui:present", committed);
  document.addEventListener("ui:invalidate", cancelPresentation);
  reduced.addEventListener("change", cancelPresentation);
  forced.addEventListener("change", cancelPresentation);
}
window.addEventListener("pagehide", () => {
  cancelPresentation();
  document.removeEventListener("ui:present", committed);
  document.removeEventListener("ui:invalidate", cancelPresentation);
  reduced.removeEventListener("change", cancelPresentation);
  forced.removeEventListener("change", cancelPresentation);
});
window.addEventListener("pageshow", mountPreferences);
mountPreferences();
