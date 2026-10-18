"use strict";
const status = document.getElementById("status");
const submit = document.getElementById("submit");
const logout = document.getElementById("logout");
const identity = document.getElementById("identity");
async function refresh() {
  const response = await fetch("/v1/session", {credentials: "same-origin"});
  if (response.ok) {
    identity.textContent = JSON.stringify(await response.json(), null, 2);
    logout.hidden = false;
  } else { identity.textContent = ""; logout.hidden = true; }
}
async function post(path, body) {
  const response = await fetch(path, {method: "POST", credentials: "same-origin", headers: {"Content-Type":"application/json"}, body: JSON.stringify(body)});
  if (!response.ok) throw new Error(response.status === 429 ? "Too many attempts. Please try later." : "Unable to complete sign-in. Request a fresh link in this browser.");
}
document.getElementById("email-form").addEventListener("submit", async event => {
  event.preventDefault(); submit.disabled = true; status.textContent = "Sending…";
  try { await post("/v1/email/start", {email: document.getElementById("email").value}); status.textContent = "Check your email. Open the link in this browser within ten minutes."; }
  catch (error) { status.textContent = error.message; }
  finally { submit.disabled = false; }
});
logout.addEventListener("click", async () => {
  logout.disabled = true;
  try { await post("/v1/logout", {}); await refresh(); status.textContent = "Signed out."; }
  catch { status.textContent = "Unable to sign out. Please retry."; }
  finally { logout.disabled = false; }
});
async function completeSignIn() {
  const token = new URLSearchParams(location.hash.slice(1)).get("token");
  history.replaceState(null, "", location.pathname);
  if (token) {
    status.textContent = "Signing in…";
    try { await post("/v1/email/finish", {token}); status.textContent = "Signed in."; }
    catch (error) { status.textContent = error.message; }
  }
  try { await refresh(); } catch { status.textContent = "Authentication is temporarily unavailable."; }
}
window.addEventListener("hashchange", () => { void completeSignIn(); });
void completeSignIn();

const resetRequest = document.getElementById("reset-request");
resetRequest.addEventListener("click", async () => {
  const email = document.getElementById("email");
  if (!email.reportValidity()) return;
  resetRequest.disabled = true; status.textContent = "Sending…";
  try {
    await post("/v1/password/reset/start", {email:email.value});
    status.textContent = "Check your email. If this mailbox has a password, open the reset link in this browser within ten minutes.";
  } catch (error) { status.textContent = error.message; }
  finally { resetRequest.disabled = false; }
});
