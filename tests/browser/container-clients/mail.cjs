'use strict';
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

function mailbox(base, origin) {
  const recipient = 'auth45-' + crypto.randomUUID() + '@example.test';
  const ids = new Set();
  async function request(path, options) {
    const response = await fetch(base + path, {...options, signal: AbortSignal.timeout(5000)});
    assert.equal(response.ok, true);
    return response;
  }
  async function messages() {
    const result = await (await request('/api/v1/search?query=' + encodeURIComponent('to:' + recipient))).json();
    return result.messages.filter(m => m.To.length === 1 && m.To[0].Address === recipient);
  }
  async function link() {
    const deadline = Date.now() + 15000;
    while (Date.now() < deadline) {
      for (const item of await messages()) {
        ids.add(item.ID);
        const message = await (await request('/api/v1/message/' + encodeURIComponent(item.ID))).json();
        assert.equal(message.To.length === 1 && message.To[0].Address === recipient, true);
        if (message.Subject !== 'Your sign-in link') continue;
        const links = (message.Text.match(/https?:\/\/[^\s]+/g) || []).map(value => new URL(value));
        const found = links.find(url => url.origin === origin && url.pathname === '/' && !url.search && /^#token=[A-Za-z0-9_-]{43}$/.test(url.hash));
        assert.equal(Boolean(found), true);
        return found.href;
      }
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    throw new Error('owned mail deadline');
  }
  async function cleanup() {
    for (const item of await messages()) ids.add(item.ID);
    if (ids.size) await request('/api/v1/messages', {method: 'DELETE',
      headers: {'Content-Type': 'application/json'}, body: JSON.stringify({IDs: [...ids]})});
    assert.equal((await messages()).length, 0);
    return ids.size;
  }
  return {recipient, link, cleanup, count: async () => (await messages()).length};
}
module.exports = {mailbox};
