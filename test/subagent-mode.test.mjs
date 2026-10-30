import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'

import { apply } from '../index.js'

const base = fs.mkdtempSync(path.join(os.tmpdir(), 'oag-sub-'))
const workspace = path.join(base, 'workspace')
fs.mkdirSync(workspace, { recursive: true })
fs.writeFileSync(path.join(base, 'outside.txt'), 'x')

function harness({ roots }) {
  const listeners = new Map()
  const ctx = {
    get(name) {
      if (name === 'commands') return { register: () => () => {} }
      if (name === 'workingDirectory') return { ensure: async () => workspace }
      if (name === 'agents') return { roots: () => roots.map(id => ({ id })) }
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
  return { ctx, listeners }
}

function run(listeners, agentId, args) {
  return listeners.get('tools/pre-execute')(
    {
      name: 'read',
      arguments: args,
      agent: { id: agentId },
      signal: new AbortController().signal,
      callId: 'call-1',
    },
    async () => ({ kind: 'allow' }),
  )
}

const outside = { file_path: path.join(base, 'outside.txt') }

test('subagentMode deny rejects outside access from a subagent', async () => {
  const { ctx, listeners } = harness({ roots: ['root'] })
  apply(ctx, { mode: 'ask', subagentMode: 'deny' })
  const result = await run(listeners, 'child', outside)
  assert.equal(result.kind, 'deny')
})

test('the main session keeps its own mode', async () => {
  const { ctx, listeners } = harness({ roots: ['root'] })
  apply(ctx, { mode: 'ask', subagentMode: 'deny' })
  const result = await run(listeners, 'root', outside)
  assert.equal(result.kind, 'ask')
})

test('an unset subagentMode inherits the main mode', async () => {
  const { ctx, listeners } = harness({ roots: ['root'] })
  apply(ctx, { mode: 'deny' })
  const result = await run(listeners, 'child', outside)
  assert.equal(result.kind, 'deny')
})
