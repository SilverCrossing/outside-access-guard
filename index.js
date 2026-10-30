/**
 * outside-access-guard — decide how tools may touch anything outside the
 * session workspace.
 *
 * The file sandbox in `workspace-write` mode restricts writes but not reads,
 * so reads outside the workspace are silently allowed by default. This plugin
 * sits on the `tools/pre-execute` waterfall (before dispatch) and applies one
 * of three modes:
 *
 *   - deny  → every outside call is rejected outright;
 *   - ask   → every outside call requires approval (default), and a call that
 *             matches a sensitive path requires a second, separate approval;
 *   - allow → nothing is intercepted.
 *
 * The mode is resolved per call in three layers: a per-session override set by
 * the human-only command `/outside-access …`, an absolute-root workspace
 * binding (`workspaces:`), and the configured default. Slash commands cannot be
 * issued by the model, so the runtime switch cannot be used to widen its own
 * access, and an override is never inherited by a subagent.
 */
import path from 'node:path'

import { classifyToolCall, DEFAULT_SENSITIVE_PATTERNS } from './classify.js'
import { createLogger } from './log.js'
import { createSessionOverrides, matchWorkspace, normalizeWorkspaces, sessionKey } from './scope.js'

export const name = 'outside-access-guard'

/** `tools` is the only hard dependency; the other services are read optionally. */
export const inject = ['tools']

const MODES = new Set(['deny', 'ask', 'allow'])
const DEFAULT_MODE = 'ask'

/** Promise-based delay used by the confirmation gap. */
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms))
}

function normalizeConfig(raw) {
  const config = raw !== null && typeof raw === 'object' ? raw : {}
  const mode = MODES.has(config.mode) ? config.mode : DEFAULT_MODE
  const extraAllowedRoots = Array.isArray(config.extraAllowedRoots)
    ? config.extraAllowedRoots.filter(value => typeof value === 'string' && value.trim() !== '')
    : []
  const sensitivePaths = Array.isArray(config.sensitivePaths)
    ? config.sensitivePaths.filter(value => typeof value === 'string' && value.trim() !== '')
    : [...DEFAULT_SENSITIVE_PATTERNS]
  if (config.subagentMode !== undefined && !MODES.has(config.subagentMode)) {
    console.warn('[outside-access-guard] config.subagentMode must be "deny", "ask" or "allow"; inheriting mode')
  }
  // Absolute-root bindings that replace the default for one workspace.
  const workspaces = normalizeWorkspaces(config.workspaces, 'workspaces', MODES, message => console.warn(`[outside-access-guard] ${message}`))
  return {
    mode,
    // `null` inherits whatever the call resolves to, so a workspace binding
    // still applies where no subagent-specific mode was configured.
    subagentMode: MODES.has(config.subagentMode) ? config.subagentMode : null,
    workspaces,
    log: config.log !== false,
    logDir: typeof config.logDir === 'string' ? config.logDir.trim() : '',
    logRetentionDays: Number.isFinite(config.logRetentionDays) ? config.logRetentionDays : 7,
    confirmGapMs: Number.isFinite(config.confirmGapMs) && config.confirmGapMs >= 0 ? Math.floor(config.confirmGapMs) : 2000,
    extraAllowedRoots,
    sensitivePaths,
    sensitiveConfirmations: config.sensitiveConfirmations === 'single' ? 'single' : 'double',
    gateShell: config.gateShell !== false,
    gatePathTools: config.gatePathTools !== false,
  }
}

/**
 * Resolve the allowed roots for one agent:
 *  - the agent's pinned starting directory (its workspace), and
 *  - user-configured extra roots (absolute, or relative to that workspace).
 *
 * `sandboxPolicy.workspaceRoot` is deliberately NOT used: in a desktop profile
 * it can be the host process directory (the profile directory), which is not
 * the session workspace and would wrongly whitelist profile files.
 */
function resolveRoots(boundary, config) {
  const candidates = [boundary]
  for (const configured of config.extraAllowedRoots) {
    const root = configured.trim()
    if (root.startsWith('~')) continue // do not guess the home directory
    candidates.push(path.isAbsolute(root) ? root : path.resolve(boundary, root))
  }

  const resolved = []
  for (const candidate of candidates) {
    if (typeof candidate !== 'string' || candidate.trim() === '') continue
    const absolute = path.resolve(candidate)
    const key = process.platform === 'win32' ? absolute.toLowerCase() : absolute
    if (resolved.some(entry => entry.key === key)) continue
    resolved.push({ key, absolute })
  }
  return resolved.map(entry => entry.absolute)
}

/**
 * The first observed directory of an agent is its workspace boundary. It is
 * pinned before the call dispatches, so an approved `working_directory` change
 * cannot move the fence afterwards.
 */
function rememberBoundary(boundaries, agent, cwd) {
  if (typeof cwd !== 'string' || cwd.trim() === '') return null
  const absolute = path.resolve(cwd)
  if (agent === undefined || agent === null || typeof agent.id !== 'string') return absolute
  const existing = boundaries.get(agent.id)
  if (existing !== undefined) return existing
  boundaries.set(agent.id, absolute)
  return absolute
}

/**
 * Whether one call comes from a subagent instead of a top-level session.
 *
 * `agents.roots()` lists agents created without an owning agent context, so
 * `subagent` and `workflow` children are absent from it. A missing service or a
 * thrown lookup counts as top-level, which keeps the configured main mode.
 */
function isSubagentCall(ctx, exec) {
  if (exec.agent === undefined || exec.agent === null) return false
  const agents = ctx.get('agents')
  if (agents === undefined || typeof agents.roots !== 'function') return false
  try {
    return !agents.roots().some(agent => agent.id === exec.agent.id)
  } catch {
    return false
  }
}

/** Current session directory, or null when it cannot be determined. */
async function sessionCwd(ctx, exec) {
  const workingDirectory = ctx.get('workingDirectory')
  if (workingDirectory === undefined || exec.agent === undefined) return null
  try {
    return await workingDirectory.ensure(exec.agent, exec.signal)
  } catch {
    return null
  }
}

function denyDecision(decision, tag) {
  return {
    kind: 'deny',
    reason: `${decision.reason} [outside-access-guard: ${tag}]`,
    info: {
      name: 'OutsideAccessDenied',
      code: 'OUTSIDE_ACCESS_DENIED',
      reason: decision.displayReason.zh,
    },
  }
}

/**
 * High-risk locations get a separate first confirmation. The ordinary tool
 * approval that follows is the second one, so both dialogs must be approved.
 * Returns null when the first confirmation passed, otherwise an immediate
 * cancel/deny decision.
 */
async function confirmHighRisk(ctx, exec, decision) {
  const approval = ctx.get('approval')
  if (approval === undefined || typeof approval.request !== 'function') {
    return denyDecision(decision, 'approval-unavailable')
  }
  if (exec.agent === undefined) {
    return denyDecision(decision, 'no-agent')
  }

  let outcome
  try {
    outcome = await approval.request({
      agent: exec.agent,
      toolName: exec.name,
      callId: exec.callId,
      reason: `High-risk outside access (confirmation 1/2): ${decision.reason}`,
      displayReason: {
        en: `Step 1 of 2 — open the final confirmation. ${decision.displayReason.en} Nothing runs here: approving only opens the second dialog.`,
        zh: `第 1/2 次确认——开启最终确认。${decision.displayReason.zh}此处不会执行：批准后会停顿，再弹出第 2 次确认。`,
      },
      signal: exec.signal,
    })
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    console.warn(`[outside-access-guard] high-risk confirmation failed: ${message}`)
    return denyDecision(decision, 'approval-failed')
  }

  if (outcome === 'allowed-once') return null
  if (outcome === 'cancelled') return { kind: 'cancel' }
  return denyDecision(decision, `approval-${outcome}`)
}

function withSecondStep(decision) {
  return {
    kind: decision.kind,
    risk: decision.risk,
    reason: decision.reason,
    displayReason: {
      en: `Step 2 of 2 — final high-risk confirmation. ${decision.displayReason.en} The call runs immediately after approval.`,
      zh: `第 2/2 次确认——高风险位置，最终确认。${decision.displayReason.zh}批准后将立即执行。`,
    },
  }
}

function modeHelp() {
  return [
    '用法：/outside-access [deny|ask|allow|reset|status]',
    '  deny  — 本会话禁止访问工作区外（直接拒绝）',
    '  ask   — 本会话工作区外每次审批；敏感路径需两次确认（默认）',
    '  allow — 本会话不拦截工作区外访问',
    '  reset — 清除本会话覆盖，回到配置/工作区绑定',
    '',
    '以上覆盖只作用于当前会话，重启后失效；子代理不受影响。',
  ].join('\n')
}

const SOURCE_LABEL = { config: '配置默认', workspace: '工作区绑定', session: '本会话覆盖' }

const MEANING = {
  deny: '禁止访问工作区外（直接拒绝）',
  ask: '工作区外每次审批；敏感路径两次确认',
  allow: '不拦截工作区外访问',
}

/**
 * Effective mode for one call: session override > workspace binding > config.
 *
 * A subagent resolves through its own knob (`subagentMode`) and then through the
 * same binding/default chain, but never through a session override or a
 * session-level relaxation.
 */
function resolveMode({ config, overrides, sessionId, cwd, scope }) {
  const override = overrides.get(sessionId)
  const binding = matchWorkspace(cwd, config.workspaces)
  const bound = binding === null ? undefined : binding.mode
  if (scope === 'subagent') {
    return {
      mode: config.subagentMode ?? bound ?? config.mode,
      source: config.subagentMode !== null ? 'config' : binding === null ? 'config' : 'workspace',
      binding,
    }
  }
  return {
    mode: override?.mode ?? bound ?? config.mode,
    source: override === undefined ? (binding === null ? 'config' : 'workspace') : 'session',
    binding,
  }
}

function statusText({ config, overrides, sessionId, cwd }) {
  const policy = resolveMode({ config, overrides, sessionId, cwd, scope: 'main' })
  const binding = policy.binding === null
    ? (config.workspaces.length === 0 ? '未配置' : '未命中（当前会话不在任何绑定根下）')
    : `${policy.binding.root} → ${policy.binding.mode}`
  return [
    `工作区外访问：本会话 ${policy.mode}（来源：${SOURCE_LABEL[policy.source]}）`,
    `配置默认：${config.mode} · 子代理：${config.subagentMode ?? '继承解析结果'}`,
    `工作区绑定：${binding}`,
    `含义：${MEANING[policy.mode]}`,
    `敏感规则：${config.sensitivePaths.length} 条`,
  ].join('\n')
}

/** The session directory an invocation addresses, or null. */
async function sessionDirFor(ctx, agent) {
  const workingDirectory = ctx.get('workingDirectory')
  if (workingDirectory === undefined || typeof workingDirectory.ensure !== 'function') return null
  if (agent === undefined || agent === null) return null
  try {
    return await workingDirectory.ensure(agent)
  } catch {
    return null
  }
}

function registerModeCommand(ctx, config, overrides, logger) {
  const commands = ctx.get('commands')
  if (commands === undefined || typeof commands.register !== 'function') {
    console.warn('[outside-access-guard] commands service unavailable; /outside-access is not registered')
    return
  }
  try {
    const definition = {
      name: 'outside-access',
      description: '切换本会话的工作区外访问模式：deny（禁止）、ask（审批）、allow（放行）、reset。',
      input: { hint: 'deny | ask | allow | reset | status' },
      handler: async (invocation) => {
        const argument = invocation.rawInput.trim().toLowerCase()
        const sessionId = sessionKey(invocation.agent)
        const cwd = await sessionDirFor(ctx, invocation.agent)
        const report = () => statusText({ config, overrides, sessionId, cwd })
        if (argument === '' || argument === 'status') {
          return { kind: 'success', text: report() }
        }
        if (MODES.has(argument)) {
          overrides.patch(sessionId, { mode: argument })
          logger.write({ event: 'mode', mode: argument, session: sessionId === '' ? undefined : sessionId })
          return { kind: 'success', text: `本会话已切换为「${argument}」。\n${report()}` }
        }
        if (argument === 'reset') {
          overrides.delete(sessionId)
          logger.write({ event: 'mode', mode: 'reset', session: sessionId === '' ? undefined : sessionId })
          return { kind: 'success', text: `已清除本会话覆盖。\n${report()}` }
        }
        return { kind: 'error', text: modeHelp() }
      },
    }
    if (typeof ctx.effect === 'function') {
      ctx.effect(() => {
        const dispose = commands.register(definition)
        return () => dispose()
      })
    } else {
      commands.register(definition)
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    console.warn(`[outside-access-guard] command registration failed: ${message}`)
  }
}

export function apply(ctx, rawConfig) {
  const config = normalizeConfig(rawConfig)
  const logger = createLogger('outside-access-guard', config)
  const pending = new Map()
  const MAX_PENDING = 256

  /**
   * Remember which call this plugin asked about, so the approval outcome can
   * be attached to it later. Bounded: a call whose approval never arrives (or
   * whose process was restarted) is dropped instead of leaking memory.
   */
  function rememberAsk(exec, decision) {
    if (exec.callId === undefined) return
    if (pending.size >= MAX_PENDING) {
      const oldest = pending.keys().next().value
      if (oldest !== undefined) pending.delete(oldest)
    }
    pending.set(exec.callId, { tool: exec.name, kind: decision.kind ?? 'outside', risk: decision.risk ?? 'normal' })
  }

  // Observation only: let the normal answerers decide, then record the outcome.
  ctx.on('approval/request', async (request, next) => {
    const outcome = await next()
    try {
      const known = request.callId !== undefined ? pending.get(request.callId) : undefined
      if (known !== undefined) {
        pending.delete(request.callId)
        logger.write({ event: 'approval', outcome, tool: known.tool, kind: known.kind, risk: known.risk, agent: request.agent?.id, callId: request.callId })
      }
    } catch {
      // Logging must never change the approval outcome.
    }
    return outcome
  })

  const overrides = createSessionOverrides()
  let warnedNoRoots = false
  const boundaries = new Map()

  registerModeCommand(ctx, config, overrides, logger)

  ctx.on('agent/disposed', payload => {
    const agent = payload !== null && typeof payload === 'object' ? payload.agent : undefined
    if (agent !== undefined && typeof agent.id === 'string') boundaries.delete(agent.id)
    const key = sessionKey(agent)
    if (key !== '') overrides.delete(key)
  })

  // Pipeline for one call:
  //   classify → (mode deny: reject) → (high risk: confirm 1/2) → ask
  // Every branch that intercepts writes one decision log line first.
  ctx.on('tools/pre-execute', async (exec, next) => {
    if (exec === null || typeof exec !== 'object' || typeof exec.name !== 'string') {
      return next()
    }
    const scope = isSubagentCall(ctx, exec) ? 'subagent' : 'main'
    const sessionId = sessionKey(exec.agent)
    if (exec.signal !== undefined && exec.signal.aborted) {
      return { kind: 'cancel' }
    }

    const cwd = await sessionCwd(ctx, exec)
    const policy = resolveMode({ config, overrides, sessionId, cwd, scope })
    const effectiveMode = policy.mode
    // Every decision line carries where the mode came from, so "why was this
    // allowed" is answerable from the log alone.
    const meta = { modeSource: policy.source, session: sessionId === '' ? undefined : sessionId }
    if (effectiveMode === 'allow') return next()

    const boundary = rememberBoundary(boundaries, exec.agent, cwd)
    if (boundary === null) {
      if (!warnedNoRoots) {
        warnedNoRoots = true
        console.warn('[outside-access-guard] cannot determine the session workspace; access gate is inactive')
      }
      return next()
    }

    const roots = resolveRoots(boundary, config)

    let decision = null
    try {
      decision = classifyToolCall({
        name: exec.name,
        args: exec.arguments,
        cwd: cwd ?? boundary,
        roots,
        gateShell: config.gateShell,
        gatePathTools: config.gatePathTools,
        sensitivePatterns: config.sensitivePaths,
      })
    } catch (error) {
      // Fail closed: an unclassifiable call still requires a human decision.
      const message = error instanceof Error ? error.message : String(error)
      console.warn(`[outside-access-guard] classification failed for ${exec.name}: ${message}`)
      decision = {
        reason: `outside-access-guard could not classify ${exec.name}: ${message}`,
        displayReason: {
          en: `The outside-access guard could not classify ${exec.name}. Approve only if you trust this call.`,
          zh: `工作区外访问守卫无法判定 ${exec.name}，请确认后再批准。`,
        },
        risk: 'normal',
      }
    }

    if (decision === null) return next()

    if (effectiveMode === 'deny') {
      logger.write({ event: 'deny', mode: effectiveMode, ...meta, scope, tool: exec.name, risk: decision.risk ?? 'normal', reason: String(decision.reason ?? '').slice(0, 300), agent: exec.agent?.id, callId: exec.callId })
      return denyDecision(decision, 'mode=deny')
    }

    if (decision.risk === 'high' && config.sensitiveConfirmations === 'double') {
      rememberAsk(exec, decision)
      logger.write({ event: 'ask', rule: 'high-risk-step1', mode: effectiveMode, ...meta, scope, tool: exec.name, risk: decision.risk, reason: String(decision.reason ?? '').slice(0, 300), agent: exec.agent?.id, callId: exec.callId })
      const first = await confirmHighRisk(ctx, exec, decision)
      if (first !== null) {
        logger.write({ event: first.kind === 'cancel' ? 'cancel' : 'deny', mode: effectiveMode, ...meta, scope, tool: exec.name, risk: decision.risk, rule: 'high-risk-step1', reason: String(decision.reason ?? '').slice(0, 300), agent: exec.agent?.id, callId: exec.callId })
        return first
      }
      decision = withSecondStep(decision)
      // A mandatory pause before the second dialog: it turns a reflex double
      // click into a decision, without changing either dialog's wording.
      if (config.confirmGapMs > 0) {
        await sleep(config.confirmGapMs)
        if (exec.signal !== undefined && exec.signal.aborted) return { kind: 'cancel' }
      }
    }

    if (exec.signal !== undefined && exec.signal.aborted) {
      return { kind: 'cancel' }
    }

    rememberAsk(exec, decision)
    logger.write({ event: 'ask', mode: effectiveMode, ...meta, scope, tool: exec.name, risk: decision.risk ?? 'normal', rule: decision.sensitivePattern ?? null, reason: String(decision.reason ?? '').slice(0, 300), agent: exec.agent?.id, callId: exec.callId })
    return {
      kind: 'ask',
      reason: decision.reason,
      displayReason: decision.displayReason,
    }
  })
}
