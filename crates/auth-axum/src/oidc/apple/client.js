'use strict';
(() => {
  const onReturn = document.body.dataset.appleReturn === 'true';
  const delivery = document.getElementById('apple-delivery');
  let returned = onReturn ? delivery?.dataset.response ?? null : null;
  delivery?.removeAttribute('data-response');
  delivery?.remove();
  history.replaceState(null, '', location.pathname);
  let stateHint = returned ? new URLSearchParams(returned).get('state') : null;
  const form = document.getElementById('confirm');
  const cancel = document.getElementById('cancel');
  const status = document.getElementById('status');
  let operation = null;
  let ready = !onReturn;
  let closed = false;
  let busy = false;
  let generation = 0;
  let controller = null;

  function render() {
    form.hidden = closed || !ready || (onReturn && !returned);
    cancel.hidden = closed || !ready || (onReturn && !stateHint);
    for (const button of document.querySelectorAll('button')) button.disabled = busy;
  }
  function discard() {
    returned = null;
    stateHint = null;
  }
  async function request(action, body, signal) {
    const prefix = operation === 'link_identity' ? '/v1/account/apple-link' : '/v1/apple/sign-in';
    const response = await fetch(`${prefix}/${action}`, {
      method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal,
      headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)
    });
    if (!response.ok || response.status !== (action === 'start' ? 200 : 204)) {
      throw Object.assign(new Error('Not confirmed'), {status: response.status});
    }
    return action === 'start' ? response.json() : null;
  }
  async function run(action) {
    if (closed || busy) return;
    busy = true;
    const stamp = generation;
    controller = new AbortController();
    render();
    try { await action(controller.signal, () => !closed && stamp === generation); }
    catch (error) {
      if (!closed && stamp === generation) {
        const reason = error.status === 503 ? 'Service unavailable.' : error.status === 429 ? 'Too many attempts.' : 'The operation was not confirmed.';
        status.textContent = `${reason} Check your session before restarting. A failed or interrupted finish cannot be repeated here.`;
      }
    } finally {
      if (stamp === generation) { busy = false; controller = null; render(); }
    }
  }
  form.addEventListener('submit', event => {
    event.preventDefault();
    if (!ready) return;
    run(async (signal, current) => {
      if (onReturn) {
        if (!returned) return;
        const response = returned;
        returned = null;
        await request('finish', operation === 'link_identity' ? {response, confirmation: 'link this account'} : {response}, signal);
        if (current()) { discard(); closed = true; status.textContent = operation === 'link_identity' ? 'Apple identity linked. Your current local session was retained.' : 'Apple sign-in completed. Your local session is available.'; }
      } else {
        const response = await request('start', {}, signal);
        if (!current()) return;
        const destination = new URL(response.authorization_url);
        if (destination.origin !== 'https://appleid.apple.com' || destination.pathname !== '/auth/authorize'
          || destination.username || destination.password || destination.hash) throw new Error('Invalid destination');
        location.assign(destination.href);
      }
    });
  });
  cancel.addEventListener('click', () => { if (!ready) return; run(async (signal, current) => {
    const state = stateHint;
    returned = null;
    await request('cancel', state ? {state} : {}, signal);
    if (current()) { discard(); closed = true; status.textContent = operation === 'link_identity' ? 'Pending link cancelled. Your current session was retained.' : 'Pending sign-in cancelled. Any current session was retained.'; }
  }); });
  window.addEventListener('pagehide', () => {
    closed = true; ready = false; generation += 1; discard(); controller?.abort(); controller = null; busy = false;
  });
  window.addEventListener('pageshow', event => {
    if (event.persisted) {
      closed = onReturn;
      ready = !onReturn;
      status.textContent = 'Page restored without return data. Check your session and open the sign-in page before restarting.';
      render();
    }
  });
  if (onReturn && !returned) status.textContent = 'No return data is available. Check your session before restarting.';
  render();
  if (onReturn && returned && stateHint) run(async (signal, current) => {
    const response = await fetch('/v1/apple/return-operation', {
      method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal,
      headers: {'Content-Type': 'application/json'}, body: JSON.stringify({state: stateHint})
    });
    if (!response.ok || response.status !== 200) throw new Error('Unknown return');
    const selected = await response.json();
    if (!current()) return;
    if (!['sign_in', 'link_identity'].includes(selected)) throw new Error('Unknown operation');
    operation = selected;
    if (operation === 'link_identity') {
      const session = await fetch('/v1/session', {credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal});
      if (!session.ok) throw new Error('No current account');
      const user = await session.json();
      if (!current()) return;
      status.textContent = `Link to current account: ${user.email || user.display_name || user.id}. Confirm only if this is the account you originally chose.`;
      document.getElementById('continue').textContent = 'Link this Apple identity';
      cancel.textContent = 'Cancel this pending link';
    }
    if (current()) ready = true;
  });
})();
