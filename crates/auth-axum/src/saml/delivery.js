'use strict';
(async () => {
  const form = document.getElementById('delivery');
  let body = new URLSearchParams(new FormData(form));
  form.remove();
  const status = document.getElementById('status');
  const controller = new AbortController();
  let operation;
  function discard() {
    if (body) { body.delete('SAMLResponse'); body.delete('RelayState'); body.delete('confirmation'); }
    body = null;
    controller.abort();
  }
  function fail() {
    discard();
    status.textContent = operation === 'delete_account'
      ? 'Unable to confirm account deletion. Return to the application and check your account.'
      : 'Unable to complete sign-in. Return to sign-in and try again.';
  }
  window.addEventListener('pagehide', discard, {once: true});
  window.addEventListener('pageshow', event => { if (event.persisted) fail(); });
  async function finish(path) {
    const response = await fetch(path, {
      method: 'POST', credentials: 'same-origin', cache: 'no-store', body, signal: controller.signal
    });
    if (!response.ok) throw new Error();
    discard();
    window.location.replace('/');
  }
  try {
    const selected = await fetch('/v1/saml/operation', {
      method: 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({RelayState: body.get('RelayState')}), signal: controller.signal
    });
    if (!selected.ok) throw new Error();
    operation = (await selected.json()).operation;
    if (controller.signal.aborted || !body) throw new Error();
    document.title = operation === 'delete_account' ? 'Delete account' : 'Sign in';
    if (operation === 'sign_in') { await finish('/v1/saml/sign-in/finish'); return; }
    if (operation !== 'delete_account') throw new Error();
    status.textContent = 'Confirm deletion of your local account. Your identity provider account remains.';
    const confirmation = document.createElement('form');
    confirmation.id = 'delete-confirm';
    const label = document.createElement('label');
    label.textContent = 'Type delete my account: ';
    const input = document.createElement('input');
    input.name = 'confirmation'; input.autocomplete = 'off'; input.required = true;
    label.append(input);
    const submit = document.createElement('button');
    submit.type = 'submit'; submit.textContent = 'Delete my account';
    confirmation.append(label, submit);
    const cancel = document.createElement('button');
    cancel.type = 'button'; cancel.textContent = 'Cancel deletion';
    document.body.append(confirmation, cancel);
    confirmation.addEventListener('submit', async event => {
      event.preventDefault();
      const phrase = input.value; input.value = '';
      if (phrase !== 'delete my account') { status.textContent = 'Type the exact confirmation phrase.'; return; }
      submit.disabled = true; cancel.disabled = true;
      try {
        body.set('confirmation', phrase);
        await finish('/v1/saml/account-delete/finish');
      } catch { confirmation.remove(); cancel.remove(); fail(); }
    });
    cancel.addEventListener('click', async () => {
      submit.disabled = true; cancel.disabled = true;
      try {
        const response = await fetch('/v1/saml/account-delete/cancel', {
          method: 'POST', credentials: 'same-origin', cache: 'no-store',
          headers: {'Content-Type': 'application/json'}, body: '{}', signal: controller.signal
        });
        if (!response.ok) throw new Error();
        discard(); confirmation.remove(); cancel.remove();
        status.textContent = 'Pending deletion cancelled.';
      } catch { confirmation.remove(); cancel.remove(); fail(); }
    });
  } catch { fail(); }
})();
