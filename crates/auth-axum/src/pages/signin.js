"use strict";
import {request, assertKey, createKey, accountId} from "/ui/browser-operations.js";
import {showAuthScreen} from "/ui/auth-screens.js";
import {element, announce, notify, submit, run, clearSecrets} from "/ui/view.js";

async function confirmedSession(refresh) {
  if (!await refresh()) throw Object.assign(new Error("Session not confirmed"), {name: "PageChangedError"});
  element("heading").focus();
}

async function signInWithPasskey(refresh, input) {
  const started = await request("/v1/passkeys/authentication/start", input);
  const credential = await assertKey(started.options);
  await request("/v1/passkeys/authentication/finish", {transaction_id: started.transaction_id, credential});
  await confirmedSession(refresh);
  notify("Signed in with a passkey.");
}

export function bindSignIn(refresh, requireCurrent, caps) {
  const sendEmail = async () => {
    await request("/v1/email/start", {email: element("email").value});
    showAuthScreen(caps, "inbox");
    element("heading").focus();
    announce("Check your email. Open the link in this browser within ten minutes.");
  };
  submit("email-form", sendEmail, "Sending your sign-in link…");
  element("email-resend").addEventListener("click", () => {
    if (element("email").checkValidity()) void run(element("email-resend"), sendEmail, "Sending a fresh sign-in link…");
  });
  submit("password-form", async () => {
    try {
      await request("/v1/password/login", {email: element("login-email").value, password: element("login-password").value});
      await confirmedSession(refresh);
      notify("Signed in.");
    } finally { clearSecrets(); }
  }, "Checking your password…");
  element("reset-request").addEventListener("click", () => {
    const email = element("login-email");
    if (!email.reportValidity()) return;
    void run(element("password-form"), async () => {
      try {
        await request("/v1/password/reset/start", {email: email.value});
        announce("If this mailbox has a password, you will receive a reset link. Open it in this browser within ten minutes.");
      } finally { clearSecrets(); }
    }, "Requesting a password reset…");
  });
  submit("passkey-form", () => signInWithPasskey(refresh, {mode: "discoverable"}), "Choose and verify your passkey…");
  submit("account-passkey-form", () => signInWithPasskey(refresh, {
    mode: "account_bound", account_id: accountId(element("passkey-account"))
  }), "Choose and verify your passkey…");
  submit("signup-form", async () => {
    const started = await request("/v1/passkeys/signup/start", {display_name: element("display-name").value});
    const credential = await createKey(started.options);
    const created = await request("/v1/passkeys/signup/registration", {transaction_id: started.transaction_id, credential});
    announce("Now verify the new passkey to finish creating your account.");
    const assertion = await assertKey(created.options);
    await request("/v1/passkeys/signup/finish", {transaction_id: created.transaction_id, credential: assertion});
    await confirmedSession(refresh);
    notify("Account created. Your passkey is ready.");
  }, "Create a passkey…");
  submit("enroll-password-form", async () => {
    const password = element("new-password");
    const confirm = element("confirm-password");
    const proposed = password.value;
    if (proposed !== confirm.value) {
      confirm.setCustomValidity("Enter the same password in both fields.");
      confirm.reportValidity();
      announce("Enter the same password in both fields.");
      return;
    }
    try {
      await requireCurrent();
      await request("/v1/password/enroll", {password: proposed});
      await confirmedSession(refresh);
      notify("Password saved. Previous sessions were signed out.");
    } finally { clearSecrets(); }
  }, "Saving your password…");
  for (const id of ["new-password", "confirm-password"]) element(id).addEventListener("input", () => element("confirm-password").setCustomValidity(""));
}

export async function finishEmail(refresh) {
  const token = new URLSearchParams(location.hash.slice(1)).get("token");
  history.replaceState(null, "", location.pathname);
  if (!token) { await refresh(); return; }
  await run(element("email-form"), async () => {
    await request("/v1/email/finish", {token});
    await confirmedSession(refresh);
    notify("Signed in.");
  }, "Confirming your email sign-in…");
}
