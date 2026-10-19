'use strict';
const assert = require('node:assert/strict');

// Only this run's random recipient namespace may be searched or removed. Never
// clear a shared mailbox, and never persist/log message bodies or proof URLs.
function mailbox(base, namespace) {
  const url = new URL(base);
  assert.equal(url.protocol, 'http:');
  assert.equal(['localhost', '127.0.0.1', '[::1]'].includes(url.hostname), true);
  assert.equal(url.username + url.password + url.search + url.hash, '');
  const recipients = new Set();
  const seen = new Set();
  async function request(path, options) {
    const response = await fetch(new URL(path, url), {...options, signal: AbortSignal.timeout(5000)});
    assert.equal(response.ok, true, 'local Mailpit request');
    return response;
  }
  function recipient(index) {
    const address = `attachment-${namespace}-${index}@example.test`;
    recipients.add(address);
    return address;
  }
  async function messages(address) {
    assert.equal(recipients.has(address), true, 'only owned test recipient');
    const response = await request(`/api/v1/search?query=${encodeURIComponent(`to:${address}`)}`);
    const data = await response.json();
    return data.messages.filter(message => message.To.length === 1 && message.To[0].Address === address);
  }
  async function proof(address, origin) {
    const deadline = Date.now() + 10000;
    while (Date.now() < deadline) {
      for (const summary of await messages(address)) {
        if (summary.Subject !== 'Confirm contact email' || seen.has(summary.ID)) continue;
        seen.add(summary.ID);
        const message = await (await request(`/api/v1/message/${encodeURIComponent(summary.ID)}`)).json();
        assert.equal(message.Subject, 'Confirm contact email');
        assert.equal(message.To.length, 1);
        assert.equal(message.To[0].Address === address, true, 'exact owned recipient');
        const match = message.Text.match(/http:\/\/localhost:\d+\/email-attach#token=([A-Za-z0-9_-]{43})/);
        assert.equal(Boolean(match), true, 'real SMTP message carries a fragment proof');
        const link = new URL(match[0]);
        assert.equal(link.origin, origin, 'trusted configured origin');
        assert.equal(link.pathname, '/email-attach');
        assert.equal(link.search, '');
        return {link: link.href, token: match[1]};
      }
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    throw new Error('owned SMTP proof timeout');
  }
  async function notices(address, expected) {
    const deadline = Date.now() + 10000;
    while (Date.now() < deadline) {
      const summaries = (await messages(address)).filter(message => message.Subject === 'Your passkeys changed');
      if (summaries.length >= expected) {
        assert.equal(summaries.length, expected, 'exact owned passkey notices');
        for (const summary of summaries) {
          const message = await (await request(`/api/v1/message/${encodeURIComponent(summary.ID)}`)).json();
          assert.equal(message.Subject, 'Your passkeys changed');
          assert.equal(message.To.length, 1);
          assert.equal(message.To[0].Address === address, true, 'verified owned notice recipient');
          assert.equal(message.Text.includes('A passkey on your authentication account was renamed or removed'), true);
          assert.equal(/https?:\/\/|#token|Native managed key|Spare browser key/.test(message.Text), false, 'no credential link or untrusted label');
        }
        return;
      }
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    throw new Error('owned passkey notice timeout');
  }
  async function cleanup() {
    const ids = new Set();
    for (const address of recipients) for (const message of await messages(address)) ids.add(message.ID);
    // An empty IDs list means delete-all in Mailpit. Never submit it.
    if (ids.size) await request('/api/v1/messages', {method: 'DELETE',
      headers: {'Content-Type': 'application/json'}, body: JSON.stringify({IDs: [...ids]})});
    for (const address of recipients) assert.equal((await messages(address)).length, 0, 'owned mail removed');
    return {messages_removed: ids.size, owned_mail_removed: true};
  }
  async function version() {
    return (await (await request('/api/v1/info')).json()).Version;
  }
  return {recipient, proof, notices, cleanup, version};
}
module.exports = {mailbox};
