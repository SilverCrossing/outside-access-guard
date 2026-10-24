import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'

import { apply } from '../index.js'

const base = fs.mkdtempSync(path.join(os.tmpdir(), 'oag-apply-'))
const workspace = path.join(base, 'workspace')
fs.mkdirSync(workspace, { recursive: true })
fs.writeFileSync(path.join(workspace, 'inside.txt'), 'inside')
fs.writeFileSync(path.join(base, 'outside.txt'), 'outside')

function commandRegistry() {
  const byName = new Map()
  return {
    register(definition) {
      byName.set(definition.name, definition)
      return () => byName.delete(definition.name)
    },
    get(name) {
      return byName.get(name)
    },
    names() {
      return [...byName.keys()]
    },
  }
}

function harness({ commands = commandRegistry(), approval } = {}) {
  const listeners = new Map()
  const ctx = {
    get(name) {
      if (name === 'commands') return commands
      if (name === 'workingDirectory') return { ensure: async () => workspace }
      if (name === 'approval') return approval
      return undefined
    },
    on(event, handler) {
      listeners.set(event, handler)
      return () => listeners.delete(event)
    },
    effect(callback) {
      const dispose = callback()
      return () => {
        if (typeof dispose === 'function') dispose()
      }
    },
  }
  return { ctx, listeners, commands }
}

async function preExecute(listeners, exec) {
  const handler = listeners.get('tools/pre-execute')
  assert.equal(typeof handler, 'function')
  return handler(exec, async () => ({ kind: 'allow' }))
}

const signal = new AbortController().signal
const agent = { id: 'agent-test' }

test('apply registers the /outside-access command', async () => {
  const { ctx, commands } = harness()
  apply(ctx, {})
  assert.deepEqual(commands.names(), ['outside-access'])

  const status = await commands.get('outside-access').handler({ rawInput: 'status' })
  assert.equal(status.kind, 'success')
  assert.match(status.text, /ask/)
})

test('command switches the in-memory mode to deny', async () => {
  const { ctx, listeners, commands } = harness()
  apply(ctx, {})

  const switched = await commands.get('outside-access').handler({ rawInput: 'deny' })
  assert.equal(switched.kind, 'success')

  const result = await preExecute(listeners, {
    name: 'read',
    arguments: { file_path: path.join(base, 'outside.txt') },
    agent,
    signal,
  })
  assert.equal(result.kind, 'deny')
})

test('invalid command argument is rejected', async () => {
  const { ctx, commands } = harness()
  apply(ctx, {})
  const result = await commands.get('outside-access').handler({ rawInput: 'nonsense' })
  assert.equal(result.kind, 'error')
})

test('ask mode returns ask for an outside path', async () => {
  const { ctx, listeners } = harness()
  apply(ctx, {})
  const result = await preExecute(listeners, {
    name: 'read',
    arguments: { file_path: path.join(base, 'outside.txt') },
    agent,
    signal,
  })
  assert.equal(result.kind, 'ask')
})

test('inside path is delegated to next()', async () => {
  const { ctx, listeners } = harness()
  apply(ctx, {})
  const result = await preExecute(listeners, {
    name: 'read',
    arguments: { file_path: path.join(workspace, 'inside.txt') },
    agent,
    signal,
  })
  assert.equal(result.kind, 'allow')
})

test('allow mode bypasses every check', async () => {
  const { ctx, listeners } = harness()
  apply(ctx, { mode: 'allow' })
  const result = await preExecute(listeners, {
    name: 'read',
    arguments: { file_path: path.join(base, 'outside.txt') },
    agent,
    signal,
  })
  assert.equal(result.kind, 'allow')
})

test('missing commands service does not break the gate', async () => {
  const { ctx, listeners } = harness({ commands: undefined })
  apply(ctx, {})
  const result = await preExecute(listeners, {
    name: 'read',
    arguments: { file_path: path.join(base, 'outside.txt') },
    agent,
    signal,
  })
  assert.equal(result.kind, 'ask')
})

test('sensitive path asks twice and denies when the first confirmation is rejected', async () => {
  const calls = []
  const approval = {
    async request(request) {
      calls.push(request)
      return 'rejected'
    },
  }
  const { ctx, listeners } = harness({ approval })
  apply(ctx, {})

  const home = path.join(base, 'home')
  const ssh = path.join(home, '.ssh')
  fs.mkdirSync(ssh, { recursive: true })
  fs.writeFileSync(path.join(ssh, 'id_rsa'), 'key')

  const result = await preExecute(listeners, {
    name: 'read',
    arguments: { file_path: path.join(ssh, 'id_rsa') },
    agent,
    signal,
  })
  assert.equal(calls.length, 1)
  assert.match(calls[0].displayReason.zh, /第 1\/2 次确认/)
  assert.equal(result.kind, 'deny')
})

test('sensitive path with both confirmations approved falls through to ask', async () => {
  const calls = []
  const approval = {
    async request(request) {
      calls.push(request)
      return 'allowed-once'
    },
  }
  const { ctx, listeners } = harness({ approval })
  apply(ctx, { confirmGapMs: 0 })

  const ssh = path.join(base, 'home2', '.ssh')
  fs.mkdirSync(ssh, { recursive: true })

  const result = await preExecute(listeners, {
    name: 'read',
    arguments: { file_path: path.join(ssh, 'id_rsa') },
    agent,
    signal,
  })
  assert.equal(calls.length, 1)
  assert.equal(result.kind, 'ask')
  assert.match(result.displayReason.zh, /第 2\/2 次确认/)
})

test('the confirmation gap delays the second dialog', async () => {
  const approval = { async request() { return 'allowed-once' } }
  const { ctx, listeners } = harness({ approval })
  apply(ctx, { confirmGapMs: 60 })

  const ssh = path.join(base, 'home3', '.ssh')
  fs.mkdirSync(ssh, { recursive: true })

  const started = Date.now()
  const result = await preExecute(listeners, {
    name: 'read',
    arguments: { file_path: path.join(ssh, 'id_rsa') },
    agent,
    signal,
  })
  assert.equal(result.kind, 'ask')
  assert.ok(Date.now() - started >= 50, 'the second dialog should wait for the configured gap')
})
