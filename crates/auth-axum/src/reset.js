"use strict";
let token;
const form = document.getElementById("reset-form");
const status = document.getElementById("status");
const save = document.getElementById("save");
function readProof() {
  token = new URLSearchParams(location.hash.slice(1)).get("token");
  history.replaceState(null, "", location.pathname);
  form.hidden = false; save.disabled = !token;
  status.textContent = token ? "Choose a new password." : "Open the reset email in the browser that requested it.";
}
window.addEventListener("hashchange", readProof);
readProof();
form.addEventListener("submit", async event => {
  event.preventDefault();
  const password = document.getElementById("password");
  const confirm = document.getElementById("confirm");
  if (password.value !== confirm.value) { status.textContent = "Passwords do not match."; confirm.focus(); return; }
  save.disabled = true; status.textContent = "Resetting password…";
  try {
    const response = await fetch("/v1/password/reset/finish", {method:"POST", credentials:"same-origin", headers:{"Content-Type":"application/json"}, body:JSON.stringify({token,password:password.value})});
    if (!response.ok) { status.textContent = response.status === 400 ? "Choose a longer password that is not common or compromised." : "Unable to reset. Request a new reset email in this browser, or try again later."; save.disabled = false; return; }
    token = null; form.hidden = true; status.textContent = "Password reset. Your previous sessions were signed out. Sign in again.";
  } catch { status.textContent = "Authentication is temporarily unavailable. Try again."; save.disabled = false; }
  finally { password.value = ""; confirm.value = ""; }
});
