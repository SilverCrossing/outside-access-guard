import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'

import { classifyShell, classifyToolCall, matchSensitive } from '../classify.js'

const base = fs.mkdtempSync(path.join(os.tmpdir(), 'oag-test-'))
const inside = path.join(base, 'workspace')
fs.mkdirSync(inside, { recursive: true })
fs.writeFileSync(path.join(inside, 'notes.txt'), 'hello')

const outside = path.join(base, 'outside')
fs.mkdirSync(outside, { recursive: true })
fs.writeFileSync(path.join(outside, 'secret.txt'), 'secret')

const roots = [inside]

function read(filePath) {
  return classifyToolCall({ name: 'read', args: { file_path: filePath }, cwd: inside, roots })
}

test('relative path inside the workspace is allowed', () => {
  assert.equal(read('notes.txt'), null)
  assert.equal(read('sub/../notes.txt'), null)
})

test('absolute path inside the workspace is allowed', () => {
  assert.equal(read(path.join(inside, 'notes.txt')), null)
})

test('parent traversal out of the workspace asks', () => {
  const decision = read('../outside/secret.txt')
  assert.ok(decision)
  assert.match(decision.reason, /read/)
})

test('absolute path outside the workspace asks', () => {
  const decision = read(path.join(outside, 'secret.txt'))
  assert.ok(decision)
  assert.equal(typeof decision.displayReason.zh, 'string')
})

test('nonexistent outside path still asks', () => {
  assert.ok(read('../outside/does-not-exist.txt'))
})

test('grep and glob without a path are allowed (they default to the workspace)', () => {
  assert.equal(classifyToolCall({ name: 'grep', args: { pattern: 'secret' }, cwd: inside, roots }), null)
  assert.equal(classifyToolCall({ name: 'glob', args: { pattern: '**/*.txt' }, cwd: inside, roots }), null)
})

test('grep path outside asks', () => {
  assert.ok(classifyToolCall({ name: 'grep', args: { pattern: 'x', path: outside }, cwd: inside, roots }))
})

test('changing the working directory outside asks', () => {
  assert.ok(
    classifyToolCall({ name: 'working_directory', args: { cd: outside }, cwd: inside, roots }),
  )
})

test('shell command with an outside absolute path asks', () => {
  assert.ok(classifyShell(`Get-Content '${path.join(outside, 'secret.txt')}'`, inside, roots))
})

test('shell command using an environment path asks', () => {
  assert.ok(classifyShell('Get-Content $env:USERPROFILE\\.ssh\\id_rsa', inside, roots))
  assert.ok(classifyShell('Get-Content %USERPROFILE%\\secret.txt', inside, roots))
})

test('shell command with parent traversal asks', () => {
  assert.ok(classifyShell('Get-Content ..\\outside\\secret.txt', inside, roots))
})

test('outside shell workdir asks', () => {
  assert.ok(classifyShell('git status', inside, roots, outside))
})

test('ordinary workspace shell commands are allowed', () => {
  assert.equal(classifyShell('git status', inside, roots), null)
  assert.equal(classifyShell('npm test -- --runInBand', inside, roots), null)
  assert.equal(classifyShell('Get-Content .\\notes.txt', inside, roots), null)
})

test('drive-relative paths ask', () => {
  assert.ok(read('C:secret.txt'))
})

test('symlink/junction inside the workspace pointing outside asks', () => {
  const link = path.join(inside, 'link-out')
  let created = false
  try {
    fs.symlinkSync(outside, link, process.platform === 'win32' ? 'junction' : 'dir')
    created = true
  } catch {
    // Symlink creation can be unavailable in restricted environments.
  }
  if (!created) return
  assert.ok(read('link-out\\secret.txt'))
})

test('user-configured extra root is allowed', () => {
  const decision = classifyToolCall({
    name: 'read',
    args: { file_path: path.join(outside, 'secret.txt') },
    cwd: inside,
    roots: [inside, outside],
  })
  assert.equal(decision, null)
})

test('ordinary outside path is normal risk', () => {
  const decision = read(path.join(outside, 'secret.txt'))
  assert.equal(decision.risk, 'normal')
})

test('SSH key outside the workspace is high risk', () => {
  const ssh = path.join(base, 'home', '.ssh')
  fs.mkdirSync(ssh, { recursive: true })
  fs.writeFileSync(path.join(ssh, 'id_rsa'), 'key')
  const decision = read(path.join(ssh, 'id_rsa'))
  assert.equal(decision.risk, 'high')
  assert.match(decision.sensitivePattern, /\.ssh/)
})

test('DSH credential file is high risk', () => {
  const dsh = path.join(base, 'home', '.dsh')
  fs.mkdirSync(dsh, { recursive: true })
  fs.writeFileSync(path.join(dsh, '.credentials.yaml'), 'token')
  const decision = read(path.join(dsh, '.credentials.yaml'))
  assert.equal(decision.risk, 'high')
  assert.equal(decision.sensitivePattern, '**/.dsh/.credentials.yaml')
})

test('browser profile is high risk', () => {
  const chrome = path.join(base, 'home', 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Default', 'Login Data')
  fs.mkdirSync(path.dirname(chrome), { recursive: true })
  fs.writeFileSync(chrome, 'db')
  const decision = read(chrome)
  assert.equal(decision.risk, 'high')
})

test('sensitive matching is case-insensitive on Windows', () => {
  if (process.platform !== 'win32') return
  const ssh = path.join(base, 'home', '.ssh')
  const decision = read(path.join(ssh, 'ID_RSA'))
  assert.equal(decision.risk, 'high')
})

test('sensitive detection can be disabled with an empty pattern list', () => {
  const decision = classifyToolCall({
    name: 'read',
    args: { file_path: path.join(base, 'home', '.ssh', 'id_rsa') },
    cwd: inside,
    roots: [inside],
    sensitivePatterns: [],
  })
  assert.equal(decision.risk, 'normal')
})

test('matchSensitive supports single-star segment matching', () => {
  assert.equal(matchSensitive('/home/u/.aws/credentials', ['**/.aws/credentials']), '**/.aws/credentials')
  assert.equal(matchSensitive('/home/u/.aws/config', ['**/.aws/credentials']), null)
})

test('high-risk shell path is flagged', () => {
  const sshKey = path.join(base, 'home', '.ssh', 'id_rsa')
  const decision = classifyToolCall({
    name: 'pwsh',
    args: { command: `Get-Content '${sshKey}'` },
    cwd: inside,
    roots,
  })
  assert.equal(decision.risk, 'high')
})
