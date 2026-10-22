'use strict';
const status = document.getElementById('status');
document.getElementById('delete-start').addEventListener('submit', async event => {
  event.preventDefault();
  const input = event.currentTarget.elements.confirmation;
  const confirmation = input.value;
  input.value = '';
  if (confirmation !== 'delete my account') { status.textContent = 'Type the exact confirmation phrase.'; return; }
  try {
    const response = await fetch('/v1/saml/account-delete/start', {
      method: 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: {'Content-Type': 'application/json'}, body: JSON.stringify({confirmation})
    });
    if (!response.ok) throw new Error();
    const result = await response.json();
    window.location.assign(result.authorization_url);
  } catch { status.textContent = 'Unable to start account deletion. Your account has not been deleted.'; }
});
document.getElementById('cancel').addEventListener('click', async () => {
  try {
    const response = await fetch('/v1/saml/account-delete/cancel', {
      method: 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: {'Content-Type': 'application/json'}, body: '{}'
    });
    status.textContent = response.ok ? 'Pending deletion cancelled. Your account remains.' : 'Unable to cancel the pending attempt. Your account remains.';
  } catch { status.textContent = 'Unable to cancel the pending attempt. Your account remains.'; }
});
