'use strict';
(() => {
  const status = document.getElementById('status');
  const actions = document.getElementById('actions');
  const list = document.getElementById('providers');
  const more = document.getElementById('more');
  let owner = null;
  let cursor = null;
  let closed = false;
  let busy = false;
  let generation = 0;
  let controller = null;
  function render() { for (const b of document.querySelectorAll('button')) b.disabled = busy || closed; }
  async function request(path, body, signal) {
    const response = await fetch(path, {method: body ? 'POST' : 'GET', credentials: 'same-origin',
      cache: 'no-store', redirect: 'error', signal,
      ...(body ? {headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)} : {})});
    if (!response.ok) throw Object.assign(new Error('Not confirmed'), {status: response.status});
    return response.status === 204 ? null : response.json();
  }
  async function run(action) {
    if (busy || closed) return;
    busy = true; const stamp = generation; controller = new AbortController(); render();
    try { await action(controller.signal, () => !closed && stamp === generation); }
    catch (error) {
      if (!closed && stamp === generation) status.textContent = error.status === 401
        ? 'Fresh retained authentication is required, or the account or pending operation changed. Check sign-in before restarting.'
        : 'The operation was not confirmed. Check your account before retrying.';
    } finally { if (stamp === generation) { busy = false; controller = null; render(); } }
  }
  async function requireOwner(expected, signal, current) {
    const user = await request('/v1/session', null, signal);
    if (!current()) throw new Error('Page changed');
    if (user.id !== expected) {
      owner = null; cursor = null; list.replaceChildren(); actions.hidden = true;
      document.getElementById('owner').textContent = '';
      throw Object.assign(new Error('Account changed'), {status: 401});
    }
  }
  async function inventory(signal, current, next = null) {
    const expected = owner;
    await requireOwner(expected, signal, current);
    const query = next ? `?after_kind=${encodeURIComponent(next.kind)}&after_id=${encodeURIComponent(next.id)}` : '';
    const page = await request(`/v1/account/providers${query}`, null, signal);
    await requireOwner(expected, signal, current);
    if (!next) list.replaceChildren();
    for (const provider of page.providers) {
      const item = document.createElement('li');
      const text = document.createElement('span'); text.textContent = `${provider.kind}: ${provider.issuer}`; item.append(text);
      if (provider.kind === 'oidc') {
        const button = document.createElement('button'); button.type = 'button'; button.className = 'btn';
        button.textContent = 'Unlink this identity';
        button.addEventListener('click', () => {
          if (busy || closed || !window.confirm('Unlink this identity from the displayed account? A usable retained method is required.')) return;
          run(async (signal, current) => {
            await requireOwner(expected, signal, current);
            await request('/v1/account/providers/oidc/unlink', {expected_owner: expected, identity: provider.id,
              confirmation: 'unlink this account'}, signal);
            if (!current()) return;
            status.textContent = 'Identity unlinked locally. Remote provider grants were not revoked.';
            await inventory(signal, current);
          });
        });
        item.append(button);
      }
      list.append(item);
    }
    cursor = page.next; more.hidden = !cursor;
  }
  for (const button of document.querySelectorAll('[data-link]')) button.addEventListener('click', () => {
    const provider = button.dataset.link; const expected = owner;
    if (!expected || busy || closed || !window.confirm(`Link a ${provider} identity to the displayed account?`)) return;
    run(async (signal, current) => {
      await requireOwner(expected, signal, current);
      const response = await request(`/v1/account/${provider}-link/start`,
        {expected_owner: expected, confirmation: 'link this account'}, signal);
      if (!current()) return;
      const destination = new URL(response.authorization_url);
      const origin = provider === 'google' ? 'https://accounts.google.com' : 'https://appleid.apple.com';
      const path = provider === 'google' ? '/o/oauth2/v2/auth' : '/auth/authorize';
      if (destination.origin !== origin || destination.pathname !== path || destination.username
        || destination.password || destination.hash) throw new Error('Invalid destination');
      location.assign(destination.href);
    });
  });
  for (const button of document.querySelectorAll('[data-cancel]')) button.addEventListener('click', () => run(async (signal, current) => {
    const expected = owner;
    await requireOwner(expected, signal, current);
    await request(`/v1/account/${button.dataset.cancel}-link/cancel`, {}, signal);
    if (current()) status.textContent = 'Pending link cancelled. Your current session was retained.';
  }));
  more.addEventListener('click', () => { const next = cursor; if (next) run((signal, current) => inventory(signal, current, next)); });
  window.addEventListener('pagehide', () => {
    closed = true; generation += 1; owner = null; cursor = null; controller?.abort(); controller = null;
    actions.hidden = true; list.replaceChildren(); document.getElementById('owner').textContent = ''; render();
  });
  window.addEventListener('pageshow', event => { if (event.persisted) status.textContent = 'Page restored. Reload to check your account before continuing.'; });
  run(async (signal, current) => {
    const user = await request('/v1/session', null, signal);
    if (!current()) return;
    owner = user.id; document.getElementById('owner').textContent = `Current account: ${user.email || user.display_name || user.id}`;
    await inventory(signal, current);
    if (current()) { actions.hidden = false; status.textContent = 'Check the displayed account before linking or unlinking.'; }
  });
})();
