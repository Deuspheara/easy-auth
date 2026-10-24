"use strict";
import {actionButton, paragraph, activity} from "/ui/view.js";

function objectRow(title, description) {
  const row = document.createElement("li");
  row.className = "object-row";
  const copy = document.createElement("div");
  copy.className = "object-copy";
  const heading = document.createElement("h3");
  heading.textContent = title;
  copy.append(heading, paragraph(description));
  row.append(copy);
  return row;
}

export function providerRow(provider) {
  let host;
  try { host = new URL(provider.issuer).hostname; } catch { host = "Connected account"; }
  return objectRow(host, provider.kind === "saml" ? "SAML organization sign-in" : "OpenID Connect sign-in");
}

export function sessionRow(session, revoke) {
  const row = objectRow(session.current ? "This browser" : "Another session", "Last active " + activity(session.last_seen_at_ms));
  const icon = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  icon.setAttribute("viewBox", "0 0 24 24");
  icon.setAttribute("class", "session-icon");
  icon.setAttribute("aria-hidden", "true");
  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("d", "M4 5h16v14H4zM4 9h16");
  icon.append(path);
  row.prepend(icon);
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
