"use strict";
import {feedback, locateFeedback, fieldError} from "/ui/feedback.js";
let token;
const form = document.getElementById("reset-form");
const save = document.getElementById("save");
function readProof() {
  locateFeedback(form);
  token = new URLSearchParams(location.hash.slice(1)).get("token");
  history.replaceState(null, "", location.pathname);
  form.hidden = false; save.disabled = !token;
  feedback(token ? "Choose a new password." : "Open the reset email in the browser that requested it.");
}
window.addEventListener("hashchange", readProof);
readProof();
form.addEventListener("submit", async event => {
  event.preventDefault();
  locateFeedback(form);
  const password = document.getElementById("password");
  const confirm = document.getElementById("confirm");
  if (password.value !== confirm.value) { fieldError(confirm, "Enter the same password in both fields."); confirm.focus(); return; }
  save.disabled = true; feedback("Resetting password…");
  try {
    const response = await fetch("/v1/password/reset/finish", {method:"POST", credentials:"same-origin", headers:{"Content-Type":"application/json"}, body:JSON.stringify({token,password:password.value})});
    if (!response.ok) { feedback(response.status === 400 ? "Choose a longer password that is not common or compromised." : "Unable to reset. Request a new reset email in this browser, or try again later.", true); save.disabled = false; return; }
    token = null; form.hidden = true; feedback("Password reset. Your previous sessions were signed out. Sign in again.");
  } catch { feedback("Authentication is temporarily unavailable. Try again.", true); save.disabled = false; }
  finally { password.value = ""; confirm.value = ""; }
});
