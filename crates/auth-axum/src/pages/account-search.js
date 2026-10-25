"use strict";
import {createSettingsSearch} from "/ui/settings-search.js";
import {element} from "/ui/view.js";
import {showAccountPanel} from "/ui/account-view.js";

export function bindAccountSearch() {
  const search = createSettingsSearch(element("main"), openSetting);
  function openSetting(id) {
    const triggers = {profile: '[data-open-account="details"]', passkeys: '#refresh-passkeys:not([hidden]), #enroll-passkey-entry:not([hidden])', password: '#password-entry', sessions: '#manage-sessions'};
    if (id === "recovery") { element("recovery-card").click(); return; }
    if (id === "providers") {
      showAccountPanel("overview");
      const heading = element("providers-card").querySelector("h3");
      if (!element("providers-card").hidden) { heading.tabIndex = -1; heading.focus(); }
      return;
    }
    document.querySelector(triggers[id] || "#account-back")?.click();
  }

  return {...search, open: openSetting};
}
