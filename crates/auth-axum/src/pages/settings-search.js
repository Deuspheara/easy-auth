"use strict";

const definitions = [
  ["profile", "Profile", "name email contact", () => true],
  ["passkeys", "Passkeys", "keys authentication security", (user, caps) => user.authentication_policy !== "provider_required" && (caps.passkeyManagement || caps.passkeyEnrollment)],
  ["password", "Password", "password sign in reset", (user, caps) => user.authentication_policy === "mailbox" && caps.passwords],
  ["sessions", "Sessions", "devices sign out logout", () => true],
  ["providers", "Connected accounts", "providers google oidc saml", user => user.authentication_policy === "provider_required"],
  ["recovery", "Account recovery", "lost access saved code backup", (user, caps) => user.authentication_policy !== "provider_required" && caps.recoverySetup]
];
export function settingsDestinations(user, caps) {
  return definitions.filter(([, , , allowed]) => allowed(user, caps)).map(([id, label, keywords]) => ({id, label, keywords}));
}
export function createSettingsSearch(main, navigate) {
  const section = document.createElement("section");
  section.className = "settings-search";
  section.hidden = true;
  section.setAttribute("aria-label", "Find account settings");
  section.innerHTML = '<label class="label sr-only" for="settings-query">Search account settings</label><div class="input-group"><input id="settings-query" type="search" placeholder="Search account settings" autocomplete="off" aria-controls="settings-results"><span data-align="start" aria-hidden="true"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"></circle><path d="m21 21-4.3-4.3"></path></svg></span><span data-align="end" data-shortcut></span></div><div id="settings-results" class="search-results item-group" hidden></div><span class="sr-only" role="status" aria-live="polite"></span>';
  const back = main.querySelector(":scope > .back-button, :scope > .companion-back");
  if (back) back.after(section); else main.prepend(section);
  const input = section.querySelector("input"), results = section.querySelector(".search-results");
  const count = section.querySelector('[role="status"]');
  for (const key of [navigator.platform.includes("Mac") ? "⌘" : "Ctrl", "K"]) {
    const hint = document.createElement("kbd"); hint.className = "kbd"; hint.textContent = key;
    section.querySelector("[data-shortcut]").append(hint);
  }
  let destinations = [];
  function clear() { input.value = ""; results.replaceChildren(); results.hidden = true; count.textContent = ""; }
  input.addEventListener("input", () => {
    results.replaceChildren();
    const query = input.value.trim().toLocaleLowerCase();
    results.hidden = !query;
    if (!query) { count.textContent = ""; return; }
    const matches = destinations.filter(item => (item.label + " " + item.keywords).toLocaleLowerCase().includes(query));
    count.textContent = matches.length ? `${matches.length} matching settings.` : "No matching settings.";
    if (!matches.length) { const empty = document.createElement("p"); empty.textContent = "No matching settings."; results.append(empty); }
    for (const item of matches) {
      const button = document.createElement("button");
      button.type = "button"; button.className = "item"; button.dataset.variant = "outline"; button.textContent = item.label;
      button.addEventListener("click", () => {
        if (document.querySelector('[aria-busy="true"]')) return;
        clear(); navigate(item.id);
      });
      results.append(button);
    }
  });
  document.addEventListener("keydown", event => {
    if (!section.hidden && (event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
      event.preventDefault(); input.focus();
    }
    if (event.key === "Escape" && section.contains(document.activeElement)) { event.preventDefault(); clear(); input.focus(); }
  });
  window.addEventListener("pagehide", () => { clear(); section.hidden = true; destinations = []; });
  return {
    update(items) { clear(); destinations = items; section.hidden = !items.length; },
    clear
  };
}
