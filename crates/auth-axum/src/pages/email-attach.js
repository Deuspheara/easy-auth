"use strict";
import {feedback, locateFeedback, fieldError} from "/ui/feedback.js";
const form = document.getElementById("attachment-form");
const button = document.getElementById("confirm");
let token;
function readProof() {
  locateFeedback(form);
  token = new URLSearchParams(location.hash.slice(1)).get("token");
  history.replaceState(null,"",location.pathname);
  form.hidden = !token;
  button.disabled = !token;
  feedback(token ? "Confirm only if you requested this contact address." : "Request a fresh confirmation from your account.");
}
window.addEventListener("hashchange",readProof);
readProof();
form.addEventListener("submit",async event => {
  event.preventDefault();
  locateFeedback(form);
  button.disabled = true;
  try {
    const response = await fetch("/v1/account/email/attachment/finish", {method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify({token})});
    if (!response.ok) {
      feedback("Unable to confirm. Sign in with your passkey and request a fresh confirmation.", true);
      button.disabled = false;
      return;
    }
    token = null;
    form.hidden = true;
    feedback("Contact email confirmed. Your passkey is still required to sign in.");
  } catch {
    feedback("Authentication is temporarily unavailable. Try again.", true);
    button.disabled = false;
  }
});
