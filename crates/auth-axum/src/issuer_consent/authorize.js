'use strict';
(() => {
  let wire = null, preview = null, busy = false, stopped = false;
  const controller = new AbortController();
  const status = document.getElementById('status');
  const prepare = document.getElementById('prepare');
  const resume = document.getElementById('resume');
  const approve = document.getElementById('approve');
  const cancel = document.getElementById('cancel');
  // Only fixed server HTML selects this UI variant; it confers no consent.
  const native = document.documentElement.dataset.nativeConsent === 'true';
  const prefix = native ? '/v1/oidc/native/consent/' : '/v1/oidc/consent/';
  const raw = location.search;
  history.replaceState(null, '', location.pathname);
  const names = ['client_id', 'response_type', 'redirect_uri', 'scope', 'state', 'nonce', 'code_challenge', 'code_challenge_method', ...(native ? ['prompt'] : [])];
  try {
    if (raw.length > 16385 || !raw.startsWith('?') || /%(?![0-9a-f]{2})/i.test(raw)) throw new Error();
    const params = new URLSearchParams(raw);
    if ([...params].length !== names.length || names.some(name => params.getAll(name).length !== 1) || [...params.keys()].some(name => !names.includes(name))) throw new Error();
    wire = Object.fromEntries(params);
    if (native && (wire.scope !== 'openid offline_access' || wire.prompt !== 'consent')) throw new Error();
  } catch {
    wire = null;
    status.textContent = 'This authorization request is invalid. Return to the application and start again.';
    prepare.disabled = true;
  }
  function disable() { prepare.disabled = resume.disabled = approve.disabled = cancel.disabled = true; }
  async function post(path, body) {
    const response = await fetch(path, { method: 'POST', credentials: 'same-origin', redirect: 'error', cache: 'no-store', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), signal: controller.signal });
    if (!response.ok) throw new Error();
    return response.json();
  }
  function showPreview(value, message) {
    preview = value; wire = null;
    document.getElementById('client').textContent = preview.client_id;
    document.getElementById('destination').textContent = preview.redirect_uri;
    if (native) {
      document.getElementById('grant-expiry').textContent = new Date(preview.grant_expires_at_us / 1000).toISOString();
      document.getElementById('idle').textContent = String(preview.idle_seconds);
    }
    document.getElementById('preview').hidden = false;
    prepare.hidden = resume.hidden = true; approve.hidden = cancel.hidden = false;
    approve.disabled = cancel.disabled = false;
    status.textContent = message;
  }
  prepare.addEventListener('click', async () => {
    if (busy || stopped || !wire) return;
    busy = true; disable();
    try {
      const prepared = await post(prefix + 'prepare', wire);
      if (stopped) return;
      showPreview(prepared, native ? 'Review the offline access limit before choosing Allow or Deny.' : 'Choose whether to allow this application.');
    } catch {
      if (!stopped) resume.disabled = false;
      status.textContent = 'Could not prepare this request. A fresh sign-in may be required. Return to the application to retry.';
    } finally { busy = false; }
  });
  resume.addEventListener('click', async () => {
    if (busy || stopped) return;
    busy = true; disable();
    try {
      const existing = await post(prefix + 'resume', {});
      if (stopped) return;
      showPreview(existing, 'Review the pending application before choosing Allow or Deny.');
    } catch {
      if (!stopped) {
        status.textContent = 'No usable pending request. Return to the application and start again.';
        prepare.disabled = !wire;
      }
    } finally { busy = false; }
  });
  async function decide(allow) {
    if (busy || stopped || !preview) return;
    busy = true; disable();
    try {
      const result = await post(`${prefix}${allow ? 'approve' : 'cancel'}`, { authorization: preview.authorization });
      if (stopped) return;
      preview = null;
      // Only the authenticated server result selects a destination. Initial query
      // fields, remote errors and page content are never navigation instructions.
      location.assign(result.redirect_uri);
    } catch {
      if (!stopped) {
        status.textContent = 'This decision could not complete. You can retry while the original request is valid.';
        approve.disabled = cancel.disabled = false;
      }
    } finally { busy = false; }
  }
  approve.addEventListener('click', () => decide(true));
  cancel.addEventListener('click', () => decide(false));
  function stop() { stopped = true; wire = preview = null; controller.abort(); disable(); }
  addEventListener('pagehide', stop, { once: true });
  addEventListener('pageshow', event => { if (event.persisted) { stop(); status.textContent = 'Return to the application and start again.'; } });
})();
