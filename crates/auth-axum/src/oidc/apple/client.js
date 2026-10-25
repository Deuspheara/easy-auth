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
  let closed = false;
  let busy = false;
  let generation = 0;
  let controller = null;

  function render() {
    form.hidden = closed || (onReturn && !returned);
    cancel.hidden = closed || (onReturn && !stateHint);
    for (const button of document.querySelectorAll('button')) button.disabled = busy;
  }
  function discard() {
    returned = null;
    stateHint = null;
  }
  async function request(action, body, signal) {
    const response = await fetch(`/v1/apple/sign-in/${action}`, {
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
    run(async (signal, current) => {
      if (onReturn) {
        if (!returned) return;
        const response = returned;
        returned = null;
        await request('finish', {response}, signal);
        if (current()) { discard(); closed = true; status.textContent = 'Apple sign-in completed. Your local session is available.'; }
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
  cancel.addEventListener('click', () => run(async (signal, current) => {
    const state = stateHint;
    returned = null;
    await request('cancel', state ? {state} : {}, signal);
    if (current()) { discard(); closed = true; status.textContent = 'Pending sign-in cancelled. Any current session was retained.'; }
  }));
  window.addEventListener('pagehide', () => {
    closed = true; generation += 1; discard(); controller?.abort(); controller = null; busy = false;
  });
  window.addEventListener('pageshow', event => {
    if (event.persisted) {
      closed = false;
      status.textContent = 'Page restored without return data. Check your session and open the sign-in page before restarting.';
      render();
    }
  });
  if (onReturn && !returned) status.textContent = 'No return data is available. Check your session before restarting.';
  render();
})();
