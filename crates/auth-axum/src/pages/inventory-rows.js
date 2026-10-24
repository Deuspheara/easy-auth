"use strict";
import {actionButton, paragraph, activity} from "/ui/view.js";

function objectRow(symbol, title, description) {
  const row = document.createElement("li");
  row.className = "object-row";
  const icon = document.createElement("span");
  icon.className = "object-icon";
  icon.setAttribute("aria-hidden", "true");
  icon.textContent = symbol;
  const copy = document.createElement("div");
  copy.className = "object-copy";
  const heading = document.createElement("h3");
  heading.textContent = title;
  copy.append(heading, paragraph(description));
  row.append(icon, copy);
  return row;
}

export function providerRow(provider) {
  let host;
  try { host = new URL(provider.issuer).hostname; } catch { host = "Connected account"; }
  return objectRow("↗", host, provider.kind === "saml" ? "SAML organization sign-in" : "OpenID Connect sign-in");
}

export function sessionRow(session, revoke) {
  const row = objectRow("▣", session.current ? "This browser" : "Another session", "Last active " + activity(session.last_seen_at_ms));
  if (session.current) {
    const badge = document.createElement("span");
    badge.className = "badge";
    badge.textContent = "Current";
    row.querySelector("h3").append(" ", badge);
  } else {
    const button = actionButton("Sign out", revoke);
    button.setAttribute("aria-label", "Sign out session");
    row.append(button);
  }
  return row;
}
