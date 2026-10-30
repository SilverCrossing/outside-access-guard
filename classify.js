/**
 * Pure classification for one tool call: allowed silently, outside the
 * workspace (approval), or outside plus a sensitive location (high risk,
 * double confirmation).
 *
 * Deliberately dependency-free (node:path + node:fs only) so it can be unit
 * tested outside the Harness process.
 *
 * Layout, top to bottom:
 *   1. path tables      — which tool argument names a filesystem target
 *   2. sensitive tables — outside locations that raise the risk
 *   3. path helpers     — containment, realpath, prepared roots, globs
 *   4. shell inspection — absolute tokens, traversal, env expansion
 *   5. classifyPath / classifyShell / classifyToolCall — the entry points
 */
import fs from 'node:fs'
import path from 'node:path'

const WINDOWS = process.platform === 'win32'

/** Tools whose argument names identify filesystem targets. */
const PATH_ARGS = Object.freeze({
  read: ['file_path'],
  read_image: ['file_path'],
  grep: ['path'],
  glob: ['path'],
  working_directory: ['cd'],
})

const SHELL_TOOLS = new Set(['pwsh', 'bash', 'shell'])

/**
 * Outside-workspace locations that normally hold credentials, private keys, or
 * browser session data. Matched against the real path with shell-style globs;
 * a match raises the call to "high risk" (double confirmation in ask mode).
 */
export const DEFAULT_SENSITIVE_PATTERNS = Object.freeze([
  '**/.ssh',
  '**/.ssh/**',
  '**/.aws',
  '**/.aws/**',
  '**/.gnupg',
  '**/.gnupg/**',
  '**/.kube',
  '**/.kube/**',
  '**/.docker/config.json',
  '**/.config/gcloud/**',
  '**/.netrc',
  '**/.git-credentials',
  '**/.npmrc',
  '**/.pypirc',
  '**/.dsh/.credentials.yaml',
  '**/.dsh/sessions/**',
  '**/.dsh/storages/**',
  '**/AppData/Roaming/Microsoft/Credentials/**',
  '**/AppData/Local/Microsoft/Credentials/**',
  '**/AppData/Local/Google/Chrome/User Data/**',
  '**/AppData/Local/Microsoft/Edge/User Data/**',
  '**/AppData/Local/BraveSoftware/**',
  '**/AppData/Roaming/Mozilla/Firefox/Profiles/**',
  '**/id_rsa',
  '**/id_rsa.*',
  '**/id_ed25519',
  '**/id_ed25519.*',
  '**/id_ecdsa',
  '**/id_ecdsa.*',
  '**/*.pfx',
  '**/*.p12',
  '**/Windows/System32/config/**',
  '**/NTDS.dit',
  '**/logins.json',
  '**/key4.db',
  '**/Login Data',
  '**/Local State',
  '**/Cookies',
])

function stripTrailingSeparator(value) {
  if (value.length <= 1) return value
  return value.replace(/[\\/]+$/, '')
}

/** Comparison key: Windows paths are case-insensitive. */
function key(value) {
  const stripped = stripTrailingSeparator(value)
  return WINDOWS ? stripped.toLowerCase() : stripped
}

export function isInside(root, target) {
  const r = key(root)
  const t = key(target)
  if (r === t) return true
  const relative = path.relative(r, t)
  return relative !== '' && !relative.startsWith('..') && !path.isAbsolute(relative)
}

/**
 * Resolve the real path of `target`, resolving the deepest existing ancestor
 * when the target itself does not exist yet. This defeats symlinks/junctions
 * that point out of the workspace.
 */
export function realpathDeep(target) {
  let current = path.resolve(target)
  const missing = []
  for (let depth = 0; depth < 64; depth += 1) {
    try {
      const real = fs.realpathSync.native
        ? fs.realpathSync.native(current)
        : fs.realpathSync(current)
      return path.resolve(real, ...missing)
    } catch {
      const parent = path.dirname(current)
      if (parent === current) return path.resolve(target)
      missing.unshift(path.basename(current))
      current = parent
    }
  }
  return path.resolve(target)
}

function prepareRoots(roots) {
  const prepared = []
  for (const root of roots) {
    if (typeof root !== 'string' || root.trim() === '') continue
    const absolute = path.resolve(root)
    prepared.push({ absolute, real: realpathDeep(absolute) })
  }
  return prepared
}

/** Accept either raw root strings or already-prepared { absolute, real } roots. */
function ensurePrepared(roots) {
  if (!Array.isArray(roots)) return []
  const first = roots[0]
  if (first !== null && typeof first === 'object' && typeof first.absolute === 'string') {
    return roots
  }
  return prepareRoots(roots)
}

function isAllowed(absolute, real, roots) {
  for (const root of roots) {
    // Both the requested path and its symlink-resolved target must stay inside.
    if (isInside(root.absolute, absolute) && isInside(root.real, real)) return true
  }
  return false
}

/**
 * Classify one path argument.
 * @returns {null | { target: string, real: string, why: string, pathLike: true }}
 */
export function classifyPath(raw, cwd, roots) {
  if (typeof raw !== 'string' || raw.trim() === '') return null
  if (raw.includes('\0')) return { target: raw, real: raw, why: 'invalid', pathLike: true }

  const prepared = ensurePrepared(roots)
  if (prepared.length === 0) return null

  const value = raw.trim()
  const base = cwd && path.isAbsolute(cwd) ? cwd : prepared[0].absolute

  // `~` expansion happens inside the shell/tool, not here; treat it as outside.
  if (value === '~' || value.startsWith('~/') || value.startsWith('~\\')) {
    return { target: value, real: value, why: 'home', pathLike: true }
  }
  // Drive-relative (`C:foo`) depends on per-drive shell state; cannot be resolved safely.
  if (/^[A-Za-z]:(?![\\/])/.test(value)) {
    return { target: value, real: value, why: 'drive-relative', pathLike: true }
  }

  const absolute = path.isAbsolute(value) ? path.normalize(value) : path.resolve(base, value)
  const real = realpathDeep(absolute)
  if (isAllowed(absolute, real, prepared)) return null
  return {
    target: absolute,
    real,
    why: path.isAbsolute(value) ? 'absolute' : 'relative',
    pathLike: true,
  }
}

const DRIVE_TOKEN = /(?:^|[\s"'`(=[,;|&<>])([A-Za-z]:[\\/][^\s"'`;|&<>)]*)/g
const UNC_TOKEN = /(?:^|[\s"'`(=[,;|&<>])(\\\\[^\s"'`;|&<>)]+)/g
const POSIX_TOKEN = /(?:^|[\s"'`(=[,;|&<>])(\/{1,2}[^\s"'`;|&<>)]*)/g
const TRAVERSAL = /(^|[\\/\s"'`(=[,;|&])\.\.([\\/\s"'`);|&]|$)/
const ENV_REFERENCE = /\$env:|\$\{[A-Za-z_]|\$HOME\b|%\w+%|(?:^|[\s"'`(=[,;|&])~([\\/\s"']|$)/i

/** Absolute-path tokens mentioned in a command line (drive, UNC, POSIX). */
function collectAbsoluteTokens(command) {
  const tokens = new Set()
  for (const regex of [DRIVE_TOKEN, UNC_TOKEN, POSIX_TOKEN]) {
    regex.lastIndex = 0
    let match
    while ((match = regex.exec(command)) !== null) tokens.add(match[1])
    regex.lastIndex = 0
  }
  return [...tokens]
}

/**
 * Best-effort shell inspection. A shell can read anything through string
 * construction, so this deliberately over-approximates: any absolute path,
 * parent traversal, or home/environment expansion asks for approval.
 */
export function classifyShell(command, cwd, roots, workdir) {
  const prepared = ensurePrepared(roots)
  if (typeof workdir === 'string' && workdir.trim() !== '') {
    const verdict = classifyPath(workdir, cwd, prepared)
    if (verdict) return verdict
  }
  if (typeof command !== 'string' || command.trim() === '') return null

  if (TRAVERSAL.test(command)) {
    return {
      target: command.length > 220 ? `${command.slice(0, 220)}…` : command,
      real: '',
      why: 'shell-traversal',
      pathLike: false,
    }
  }
  if (ENV_REFERENCE.test(command)) {
    return {
      target: command.length > 220 ? `${command.slice(0, 220)}…` : command,
      real: '',
      why: 'shell-environment',
      pathLike: false,
    }
  }
  for (const token of collectAbsoluteTokens(command)) {
    const verdict = classifyPath(token, cwd, prepared)
    if (verdict) return verdict
  }
  return null
}

const regexCache = new Map()

function globToRegExp(glob) {
  const cached = regexCache.get(glob)
  if (cached !== undefined) return cached
  let out = '^'
  for (let index = 0; index < glob.length; index += 1) {
    const char = glob[index]
    if (char === '*') {
      if (glob[index + 1] === '*') {
        out += '.*'
        index += 1
      } else {
        out += '[^/]*'
      }
    } else if (char === '?') {
      out += '[^/]'
    } else if ('\\^$.|+()[]{}'.includes(char)) {
      out += `\\${char}`
    } else {
      out += char
    }
  }
  const regex = new RegExp(`${out}$`, WINDOWS ? 'i' : '')
  regexCache.set(glob, regex)
  return regex
}

/** Normalize an absolute path for glob matching. */
function globPath(target) {
  return path.resolve(target).replace(/\\/g, '/')
}

/**
 * Return the first sensitive pattern matching `target`, or null.
 * Matching uses both the lexical path and its real path.
 */
export function matchSensitive(target, patterns = DEFAULT_SENSITIVE_PATTERNS) {
  if (typeof target !== 'string' || target.trim() === '') return null
  const candidates = new Set([globPath(target)])
  try {
    candidates.add(globPath(realpathDeep(target)))
  } catch {
    // keep the lexical candidate
  }
  for (const pattern of patterns) {
    if (typeof pattern !== 'string' || pattern.trim() === '') continue
    const regex = globToRegExp(pattern.trim())
    for (const candidate of candidates) {
      if (regex.test(candidate)) return pattern
    }
  }
  return null
}

const WHY_TEXT = {
  absolute: {
    en: 'is an absolute path outside the session workspace',
    zh: '指向会话工作区之外的绝对路径',
  },
  relative: {
    en: 'resolves outside the session workspace',
    zh: '解析后落在会话工作区之外',
  },
  home: {
    en: 'uses the user home directory outside the session workspace',
    zh: '指向会话工作区之外的用户主目录',
  },
  'drive-relative': {
    en: 'uses a drive-relative path that cannot be checked safely',
    zh: '使用无法安全判定的盘符相对路径',
  },
  invalid: {
    en: 'contains an invalid path character',
    zh: '包含非法路径字符',
  },
  'shell-traversal': {
    en: 'contains a parent-directory traversal',
    zh: '包含上级目录跳转（..）',
  },
  'shell-environment': {
    en: 'expands a home-directory or environment path outside the workspace',
    zh: '展开了工作区之外的主目录或环境变量路径',
  },
}

const TOOL_TEXT = {
  read: { en: 'read a file', zh: '读取文件' },
  read_image: { en: 'read an image', zh: '读取图片' },
  grep: { en: 'search files', zh: '搜索文件内容' },
  glob: { en: 'scan directories', zh: '扫描目录' },
  working_directory: { en: 'change the working directory', zh: '切换工作目录' },
  pwsh: { en: 'run a shell command', zh: '执行 shell 命令' },
  bash: { en: 'run a shell command', zh: '执行 shell 命令' },
  shell: { en: 'run a shell command', zh: '执行 shell 命令' },
}

function summarize(tool, target, why, matched = null) {
  const action = TOOL_TEXT[tool] ?? { en: 'access a path', zh: '访问路径' }
  const reason = WHY_TEXT[why] ?? WHY_TEXT.absolute
  const shown = String(target)
  const tailEn = matched === null || matched === '' ? '' : ` [matched path: ${matched}]`
  const tailZh = matched === null || matched === '' ? '' : ` ［命中路径：${matched}］`
  return {
    reason: `${tool} would ${action.en}: ${shown}${tailEn} — ${reason.en}.`,
    displayReason: {
      en: `Approval required outside the workspace: ${tool} would ${action.en}: ${shown}${tailEn} (${reason.en}).`,
      zh: `访问工作区外需要审批：${tool} 将${action.zh}：${shown}${tailZh}（${reason.zh}）。`,
    },
  }
}

/**
 * Classify one tool call.
 *
 * @param {object} input
 * @param {string} input.name tool name
 * @param {unknown} input.args parsed arguments
 * @param {string | undefined} input.cwd current session directory
 * @param {string[]} input.roots allowed roots (workspace first)
 * @param {boolean} [input.gateShell]
 * @param {boolean} [input.gatePathTools]
 * @param {string[]} [input.sensitivePatterns]
 * @returns {null | {
 *   reason: string,
 *   displayReason: { en: string, zh: string },
 *   risk: 'normal' | 'high',
 *   sensitivePattern?: string,
 * }}
 */
export function classifyToolCall({
  name,
  args,
  cwd,
  roots,
  gateShell = true,
  gatePathTools = true,
  sensitivePatterns = DEFAULT_SENSITIVE_PATTERNS,
}) {
  if (typeof name !== 'string') return null
  const prepared = prepareRoots(Array.isArray(roots) ? roots : [])
  if (prepared.length === 0) return null

  let verdict = null
  if (SHELL_TOOLS.has(name)) {
    if (!gateShell) return null
    if (args === null || typeof args !== 'object') return null
    verdict = classifyShell(args.command, cwd, prepared, args.workdir)
  } else {
    if (!gatePathTools) return null
    const keys = PATH_ARGS[name]
    if (!keys) return null
    if (args === null || typeof args !== 'object') return null
    for (const field of keys) {
      verdict = classifyPath(args[field], cwd, prepared)
      if (verdict) break
    }
  }
  if (!verdict) return null

  // A shell gate is judged on the whole command, so the card must show the
  // command. The matched path is appended instead of substituted: a reader who
  // only sees `D:\` cannot tell what is about to run.
  const command = SHELL_TOOLS.has(name) && args !== null && typeof args === 'object' && typeof args.command === 'string'
    ? args.command.trim()
    : ''
  const display = command === ''
    ? verdict.target
    : command.length > 240 ? `${command.slice(0, 240)}…` : command
  const matched = command === '' || verdict.target === display ? null : verdict.target

  const summary = summarize(name, display, verdict.why, matched)
  if (!verdict.pathLike) return { ...summary, risk: 'normal' }

  const sensitivePattern = matchSensitive(verdict.real || verdict.target, sensitivePatterns)
  if (!sensitivePattern) return { ...summary, risk: 'normal' }

  const tailEn = matched === null ? '' : ` [matched path: ${matched}]`
  const tailZh = matched === null ? '' : ` ［命中路径：${matched}］`
  return {
    reason: `HIGH RISK: ${summary.reason} Sensitive rule: ${sensitivePattern}.`,
    displayReason: {
      en: `⚠ HIGH RISK outside access: ${name} → ${display}${tailEn} matches sensitive rule "${sensitivePattern}" (credentials, private keys, or browser session data). ${summary.displayReason.en}`,
      zh: `⚠ 高风险工作区外访问：${name} → ${display}${tailZh} 命中敏感规则「${sensitivePattern}」（凭据、私钥或浏览器会话数据）。${summary.displayReason.zh}`,
    },
    risk: 'high',
    sensitivePattern,
  }
}
