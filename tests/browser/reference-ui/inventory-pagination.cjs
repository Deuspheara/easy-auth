'use strict';
// Isolated presentation tests: no HTTP server, authentication, session or proof.
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const vm = require('node:vm');
const path = require('node:path');

async function controller() {
  const nodes = new Map(), requests = [], replies = [];
  const element = id => {
    if (!nodes.has(id)) nodes.set(id, {
      hidden: true, children: [], dataset: {}, textContent: '',
      replaceChildren() { this.children = []; }, append(value) { this.children.push(value); },
      addEventListener() {}, removeAttribute() {}
    });
    return nodes.get(id);
  };
  const noop = () => {};
  const dependencies = {
    '/ui/inventory-rows.js': {providerRow: row => row, sessionRow: row => row},
    '/ui/account-view.js': {updateMethodsVisibility: noop},
    '/ui/browser-operations.js': {request: async url => {
      requests.push(url);
      assert.notEqual(replies.length, 0, 'every inventory read has an explicit test outcome');
      const reply = replies.shift();
      if (reply instanceof Error) throw reply;
      return reply;
    }},
    '/ui/view.js': {element, cancelPresentation: noop, announce: noop, notify: noop,
      errorMessage: () => 'Read failed', paragraph: value => value, date: () => 'date',
      run: async (_, action) => action(), confirmAction: async () => false, submit: noop}
  };
  const context = vm.createContext({URLSearchParams, document: {createElement: () => ({append() {}})}});
  const source = await fs.readFile(path.join(__dirname, '../../../crates/auth-axum/src/pages/account.js'), 'utf8');
  const module = new vm.SourceTextModule(source, {context});
  await module.link(specifier => {
    const exports = dependencies[specifier];
    assert.ok(exports, 'only fixed presentation dependencies are stubbed');
    return new vm.SyntheticModule(Object.keys(exports), function () {
      for (const [name, value] of Object.entries(exports)) this.setExport(name, value);
    }, {context});
  });
  await module.evaluate();
  module.namespace.bindAccount(noop, async () => {});
  return {element, requests, replies, api: module.namespace};
}

async function pagination(kind, load, firstCursor, latestCursor) {
  const {element, requests, replies, api} = await controller();
  const first = {id: 'first'}, latest = {id: 'latest'};
  replies.push({[kind]: [first], next: firstCursor});
  await api[load]();
  const continuation = kind === 'sessions'
    ? '/v1/sessions?after=' + firstCursor
    : '/v1/account/providers?' + new URLSearchParams({after_kind: firstCursor.kind, after_id: firstCursor.id});
  replies.push(new Error('continuation unavailable'));
  await api[load](false);
  assert.equal(requests.at(-1), continuation);
  assert.deepEqual(element(kind).children, [first], 'failed continuation preserves accepted rows');
  assert.equal(element('more-' + kind).hidden, false, 'failed continuation remains explicitly retryable');
  replies.push(new Error('reload unavailable'));
  await api[load]();
  assert.equal(element(kind).children.length, 0, 'reload invalidates the previous page');
  assert.equal(element('more-' + kind).hidden, true, 'failed reload cannot offer an obsolete continuation');
  // Even a direct continuation call must not reuse a discarded cursor.
  replies.push({[kind]: [latest], next: latestCursor});
  await api[load](false);
  assert.equal(requests.at(-1), kind === 'sessions' ? '/v1/sessions' : '/v1/account/providers');
  assert.deepEqual(element(kind).children, [latest]);
  replies.push({[kind]: [], next: null});
  await api[load](false);
  assert.equal(requests.at(-1).includes(kind === 'sessions' ? 'after=latest' : 'after_id=latest'), true);
  assert.equal(element('more-' + kind).hidden, true);
}

async function main() {
  await pagination('sessions', 'loadSessions', 'first', 'latest');
  await pagination('providers', 'loadProviders', {kind: 'oidc', id: 'first'}, {kind: 'saml', id: 'latest'});
  console.log('Inventory pagination presentation: 2 passed');
}
main().catch(error => { console.error(error); process.exitCode = 1; });
