"use strict";
const form = document.getElementById("attachment-form");
const button = document.getElementById("confirm");
const status = document.getElementById("status");
let token;
function readProof() {
  token = new URLSearchParams(location.hash.slice(1)).get("token");
  history.replaceState(null,"",location.pathname);
  form.hidden = !token;
  button.disabled = !token;
  status.textContent = token ? "Confirm only if you requested this contact address." : "Request a fresh confirmation from your account.";
}
window.addEventListener("hashchange",readProof);
readProof();
form.addEventListener("submit",async event => {
  event.preventDefault();
  button.disabled = true;
  try {
    const response = await fetch("/v1/account/email/attachment/finish", {method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify({token})});
    if (!response.ok) {
      status.textContent = "Unable to confirm. Sign in with your passkey and request a fresh confirmation.";
      button.disabled = false;
      return;
    }
    token = null;
    form.hidden = true;
    status.textContent = "Contact email confirmed. Your passkey is still required to sign in.";
  } catch {
    status.textContent = "Authentication is temporarily unavailable. Try again.";
    button.disabled = false;
  }
});
