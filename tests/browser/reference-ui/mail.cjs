'use strict';
const assert = require('node:assert/strict');
const {mailbox} = require('../passkeys/attachment/mail.cjs');

function ownedMail(base, namespace) {
  const owned = mailbox(base, namespace);
  const seen = new Set();
  const recipients = new Set();
  function recipient(index) {
    const address = owned.recipient(index);
    recipients.add(address);
    return address;
  }
  async function get(path) {
    const response = await fetch(new URL(path, base), {signal: AbortSignal.timeout(5000)});
    assert.equal(response.ok, true, 'owned Mailpit response');
    return response.json();
  }
  async function proof(address, origin, subject, pathname) {
    assert.equal(recipients.has(address), true, 'only exact owned recipients');
    const deadline = Date.now() + 10000;
    while (Date.now() < deadline) {
      const data = await get('/api/v1/search?query=' + encodeURIComponent('to:' + address));
      for (const summary of data.messages) {
        if (summary.Subject !== subject || seen.has(summary.ID)) continue;
        if (summary.To.length !== 1 || summary.To[0].Address !== address) continue;
        const message = await get('/api/v1/message/' + encodeURIComponent(summary.ID));
        assert.equal(message.To.length === 1 && message.To[0].Address === address, true);
        const links = message.Text.match(/http:\/\/localhost:\d+\/[^\s]*#token=[A-Za-z0-9_-]{43}/g) || [];
        const link = links.map(value => new URL(value)).find(value => value.origin === origin && value.pathname === pathname);
        assert.equal(Boolean(link), true, 'owned exact-origin SMTP fragment link');
        assert.equal(link.search, '');
        assert.equal(/^#token=[A-Za-z0-9_-]{43}$/.test(link.hash), true);
        seen.add(summary.ID);
        return link.href;
      }
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    throw new Error('owned mail proof deadline');
  }
  return {...owned, recipient, link: proof};
}
module.exports = {ownedMail};
