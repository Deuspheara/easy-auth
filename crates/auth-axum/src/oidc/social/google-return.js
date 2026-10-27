'use strict';
(() => {
  let query = location.search.startsWith('?') && !location.hash ? location.search.slice(1) : null;
  history.replaceState(null, '', location.pathname);
  let hint = query ? new URLSearchParams(query).get('state') : null;
  const form = document.getElementById('confirm'); const cancel = document.getElementById('cancel');
  const status = document.getElementById('status');
  let closed = false; let busy = false; let ready = false; let generation = 0; let controller = null;
  function render() { form.hidden = closed || !ready || !query; cancel.hidden = closed || !ready || !hint;
    for (const b of document.querySelectorAll('button')) b.disabled = busy; }
  async function request(path, body, signal) {
    const response = await fetch(path, {method: body ? 'POST' : 'GET', credentials: 'same-origin', cache: 'no-store',
      redirect: 'error', signal, ...(body ? {headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)} : {})});
    if (!response.ok) throw new Error('Not confirmed');
    return response.status === 204 ? null : response.json();
  }
  async function run(action) {
    if (closed || busy) return;
    busy = true; const stamp = generation; controller = new AbortController(); render();
    try { await action(controller.signal, () => !closed && stamp === generation); }
    catch { if (!closed && stamp === generation) status.textContent = 'Link was not confirmed. Check your account and fresh authentication before restarting. This return cannot be retried here.'; }
    finally { if (stamp === generation) { busy = false; controller = null; render(); } }
  }
  form.addEventListener('submit', event => { event.preventDefault(); if (!ready || !query) return;
    run(async (signal, current) => {
      const returned = query; query = null;
      await request('/v1/account/google-link/finish', {query: returned, confirmation: 'link this account'}, signal);
      if (current()) { hint = null; closed = true; status.textContent = 'Google identity linked. Your current local session was retained.'; }
    });
  });
  cancel.addEventListener('click', () => { if (!ready || !hint) return; run(async (signal, current) => {
    const state = hint; query = null;
    await request('/v1/account/google-link/cancel', {state}, signal);
    if (current()) { hint = null; closed = true; status.textContent = 'Pending link cancelled. Your session was retained.'; }
  }); });
  window.addEventListener('pagehide', () => {
    closed = true; generation += 1; query = null; hint = null; ready = false; controller?.abort(); controller = null;
    document.getElementById('owner').textContent = ''; render();
  });
  window.addEventListener('pageshow', event => { if (event.persisted) status.textContent = 'Page restored without return data. Check linked accounts before restarting.'; });
  render();
  if (query && hint) run(async (signal, current) => {
    const user = await request('/v1/session', null, signal);
    if (!current()) return;
    document.getElementById('owner').textContent = `Current account: ${user.email || user.display_name || user.id}`;
    ready = true; status.textContent = 'Confirm only if this is the account you originally chose to link.';
  });
  else { query = null; hint = null; status.textContent = 'No usable return data. Check linked accounts before restarting.'; }
})();
