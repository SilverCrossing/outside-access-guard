import assert from 'node:assert/strict'
import test from 'node:test'

import { classifyToolCall } from '../classify.js'

const cwd = process.cwd()
const roots = [cwd]

function call(name, args) {
  return classifyToolCall({ name, args, cwd, roots })
}

test('a shell command shows the command, not just the matched path', () => {
  const decision = call('pwsh', { command: 'Get-ChildItem D:\\ -Force | Select-Object Name' })
  assert.ok(decision)
  assert.match(decision.reason, /Get-ChildItem D:\\ -Force/)
  assert.match(decision.reason, /matched path: D:\\/)
  assert.match(decision.displayReason.zh, / ［命中路径：D:\\］/)
})

test('an environment expansion keeps the command and needs no matched tail', () => {
  const decision = call('pwsh', { command: 'Get-ChildItem $env:USERPROFILE' })
  assert.ok(decision)
  assert.match(decision.reason, /\$env:USERPROFILE/)
  assert.doesNotMatch(decision.reason, /matched path:/)
})

test('path tools still show the path they touch', () => {
  const decision = call('read', { file_path: 'D:\\outside.txt' })
  assert.ok(decision)
  assert.match(decision.reason, /D:\\outside\.txt/)
})
