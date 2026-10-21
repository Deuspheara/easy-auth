'use strict';
const status = document.getElementById('status');
async function request(action) {
  return fetch(`/v1/saml/sign-in/${action}`, {
    method: 'POST', credentials: 'same-origin', cache: 'no-store',
    headers: {'Content-Type': 'application/json'}, body: '{}'
  });
}
document.getElementById('start').addEventListener('click', async () => {
  try {
    const response = await request('start');
    if (!response.ok) throw new Error();
    const result = await response.json();
    window.location.assign(result.authorization_url);
  } catch { status.textContent = 'Unable to start sign-in. Cancel the pending attempt or sign out, then try again.'; }
});
document.getElementById('cancel').addEventListener('click', async () => {
  try { await request('cancel'); status.textContent = 'Sign-in cancelled.'; }
  catch { status.textContent = 'Unable to cancel sign-in. Please try again.'; }
});
