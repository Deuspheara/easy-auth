"use strict";
import {clearFeedback} from "/ui/feedback.js";
import {cancelPresentation, present, element, clearSecrets} from "/ui/view.js";

const screens = {
  email: ["Welcome back", "Sign in to your account"],
  password: ["Sign in with password", "Welcome back. Enter your email and password.", "passwords"],
  signup: ["Create your account", "A secure start, with a passkey on your device.", "passkeySignup"],
  help: ["Let’s get you signed in", "Choose the option that works for your account."],
  "account-passkey": ["Use your account ID", "Find the passkey you saved for this account.", "passkeySignin"],
  inbox: ["Check your email", "Open the link to continue."]
};

// Views are presentation only. A query never enables a method or supplies proof.
export function showAuthScreen(caps, requested = "email") {
  let name = Object.hasOwn(screens, requested) ? requested : "email";
  const capability = screens[name][2];
  if (capability && caps[capability] !== true) name = "email";
  cancelPresentation();
  clearFeedback();
  clearSecrets();
  for (const node of document.querySelectorAll("[data-auth-screen]")) node.hidden = node.dataset.authScreen !== name;
  element("heading").textContent = screens[name][0];
  element("intro").textContent = screens[name][1];
  present(document.querySelector(`[data-auth-screen="${name}"]`));
}
