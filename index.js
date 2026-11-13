import { appendFile, mkdir, readdir, readFile, unlink, writeFile } from 'node:fs/promises'
import { homedir } from 'node:os'
import { join } from 'node:path'

export const name = 'net-consent'

export const inject = ['tools', 'userQuestions', 'webServer']

const STATE_DIR = join(homedir(), '.dsh', 'net-consent')
const STATE_FILE = join(STATE_DIR, 'state.json')
const AUDIT_DIR = join(STATE_DIR, 'audit')

const POLICIES = ['allow', 'ask', 'deny']
const LEGACY_POLICY = { off: 'allow', observe: 'allow' }

export function normalizePolicy(value, fallback = 'ask') {
  const mapped = LEGACY_POLICY[value] ?? value
  return POLICIES.includes(mapped) ? mapped : fallback
}

const DEFAULTS = {
  mode: 'ask',
  shellMode: 'ask',
  allowLocal: true,
  askTimeoutMs: 30000,
  onTimeout: 'deny',
  audit: true,
  auditRetentionDays: 30,
  allowlist: [],
  purposes: true,
  internalTools: [
    'ask_user_question', 'todo_write', 'read', 'write', 'edit', 'glob', 'grep',
    'skill', 'present', 'compress', 'decompress', 'acp_status', 'acp_cache',
    'search_context', 'save_token_expand', 'wait_agent', 'send_message',
    'list_agents', 'list_subagent_models', 'job_output', 'job_list', 'job_kill',
    'terminal_read', 'terminal_list', 'terminal_close', 'user_terminal_list',
    'user_terminal_read', 'working_directory', 'load_workspace_dependencies',
    'get_goal', 'create_goal', 'update_goal', 'schedule_list', 'schedule_view',
    'screen_view', 'desktop_control', 'desktop_sequence',
    'acp_read_original_image', 'read_image', 'terminal_signal',
  ],
}

const WRITABLE = [
  'mode', 'shellMode', 'allowLocal', 'askTimeoutMs', 'onTimeout',
  'audit', 'auditRetentionDays', 'allowlist', 'purposes',
]

const NET_TOOL = /(^web_(fetch|search)$)|(^fetch$)|(^http_)|(browser|playwright|puppeteer|websearch|search_web|selenium|chrome_|navigate)/i

const SHELL_TOOL = /^(pwsh|powershell|bash|sh|zsh|cmd|shell|terminal|exec|run_code|process|spawn)/i

const NET_VERB = new RegExp([
  String.raw`\b(curl|wget|aria2c|yt-dlp|youtube-dl|axel|httpie|ncat|netcat|telnet|socat)\b`,
  String.raw`(^|[\s;&|(])nc\s+(-|\d)`,
  String.raw`\b(ssh|scp|sftp|rsync|ftp|tftp|ssh-keyscan)\b`,
  String.raw`\bgit\s+(clone|fetch|pull|push|ls-remote|submodule|archive\s+--remote|remote\s+update)\b`,
  String.raw`\b(pnpm|npm|yarn|bun|npx|pnpx|pipx|uvx)\b[^\n]{0,80}\b(install|i|add|update|up|upgrade|view|info|search|publish|pack|dlx|create)\b`,
  String.raw`\bpip3?\s+(install|download|wheel)\b`,
  String.raw`\b(python|py|node)\b[^\n]{0,60}\b(urllib|requests|httpx|aiohttp|socket|fetch|https?\.request|axios|got|undici)\b`,
  String.raw`\b(cargo|rustup|go|gem|composer|dotnet|nuget|choco|scoop|winget|brew|apt|apt-get|yum|dnf|apk|pacman)\b[^\n]{0,60}\b(install|add|update|upgrade|download|get|fetch|pull)\b`,
  String.raw`\b(snap\s+(install|refresh|download)|flatpak\s+(install|update|remote-add)|pacman\s+-S|zypper\s+(in|install|update)|nix-env\s+-iA?|nix\s+(profile\s+install|flake\s+update)|apk\s+add)\b`,
  String.raw`\b(lynx|w3m|links2|mosh|smbclient)\b`,
  String.raw`\bsvn\s+(checkout|co|update|up|commit|export|ls|cat|log|diff|switch|import|merge)\b`,
  String.raw`\b(docker|podman)\s+(pull|push|login|buildx)\b`,
  String.raw`\b(kubectl|helm|aws|az|gcloud|gh|heroku|vercel|netlify|firebase|terraform|ansible|oci)\b`,
  String.raw`(?<![\w-])(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm|Start-BitsTransfer|Test-NetConnection|tnc|Resolve-DnsName|nslookup|dig|ping|tracert|mtr)\b`,
  String.raw`\b(openssl\s+s_client|ssrf|webhook)\b`,
].join('|'), 'i')

const URL_RE = /https?:\/\/([^\s'"`<>()/?#:]+)/gi
const SCP_RE = /\b[a-z0-9._-]+@([a-z0-9.-]+\.[a-z]{2,})[:-]/gi

const PRIVATE_HOST = /^(localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[?::1\]?|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|169\.254\.\d+\.\d+)$/i
const PRIVATE_SUFFIX = /\.(local|lan|internal|home\.arpa|localhost)$/i

function isPrivateHost(host) {
  const h = String(host).toLowerCase().replace(/^\[|\]$/g, '')
  if (PRIVATE_HOST.test(h)) return true
  if (PRIVATE_SUFFIX.test(h)) return true
  if (!h.includes('.') && !h.includes(':')) return true
  return false
}

function asStrings(value, out = [], depth = 0) {
  if (depth > 3 || value === null || value === undefined) return out
  if (typeof value === 'string') { out.push(value); return out }
  if (Array.isArray(value)) { for (const v of value) asStrings(v, out, depth + 1); return out }
  if (typeof value === 'object') { for (const v of Object.values(value)) asStrings(v, out, depth + 1) }
  return out
}

function hostsIn(text) {
  const hosts = new Set()
  for (const m of String(text).matchAll(URL_RE)) hosts.add(m[1].toLowerCase())
  for (const m of String(text).matchAll(SCP_RE)) hosts.add(m[1].toLowerCase())
  return [...hosts]
}

function isHostEntry(entry) {
  const e = String(entry ?? '').trim()
  if (!e) return false
  if (e === '*' || e.startsWith('*.')) return true
  if (e.includes(':')) return true
  if (/^[\d.]+$/.test(e)) return true
  if (/^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(e)) return true
  return /^localhost$/i.test(e)
}

function hostAllowed(host, list) {
  const h = String(host ?? '').toLowerCase()
  return (list ?? []).some(item => {
    const p = String(item).toLowerCase().trim()
    if (!p) return false
    if (p === '*') return true
    if (p.startsWith('*.')) return h === p.slice(2) || h.endsWith(p.slice(1))
    return h === p || h.endsWith('.' + p)
  })
}

function toolMatches(tool, list) {
  const t = String(tool ?? '').toLowerCase()
  return (list ?? []).some(item => {
    const p = String(item).toLowerCase().trim()
    if (!p) return false
    if (p === '*') return true
    if (p.endsWith('*')) return t.startsWith(p.slice(0, -1))
    return t === p
  })
}

function commandMatches(command, list) {
  const text = String(command ?? '')
  if (!text) return false
  return (list ?? []).some(item => {
    const p = String(item).trim()
    if (!p || isHostEntry(p)) return false
    const escaped = p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    return new RegExp(`(?<![\\w.-])${escaped}(?![\\w.-])`, 'i').test(text)
  })
}

function classify(exec, cfg) {
  const tool = String(exec.name ?? '')
  const lower = tool.toLowerCase()
  if ((cfg.internalTools ?? DEFAULTS.internalTools).some(t => lower === String(t).toLowerCase())) return null

  const strings = asStrings(exec.arguments)
  const joined = strings.join('\n')
  const hosts = hostsIn(joined)
  const preview = (strings.find(s => s.length > 3) ?? '').slice(0, 400)

  if (NET_TOOL.test(tool)) return { network: true, kind: 'tool', hosts, preview }
  if (SHELL_TOOL.test(tool)) {
    const command = strings.join(' ')
    if (NET_VERB.test(command) || hosts.length > 0) return { network: true, kind: 'shell', hosts, command, preview }
    return null
  }
  if (hosts.length > 0) return { network: true, kind: 'tool', hosts, preview }
  return null
}

function allowlisted(verdict, cfg) {
  const entries = Array.isArray(cfg.allowlist) ? cfg.allowlist : []
  if (entries.length === 0) return null
  const tool = String(verdict?.tool ?? '').toLowerCase()
  const hosts = verdict?.hosts ?? []

  const toolHit = entries.find(e => !isHostEntry(e) && toolMatches(tool, [e]))
  if (toolHit) return { entry: toolHit, kind: 'tool' }

  if (hosts.length > 0) {
    const hostEntries = entries.filter(isHostEntry)
    if (hosts.every(h => hostAllowed(h, hostEntries))) return { entry: hostEntries.join(','), kind: 'host' }
  }

  if (verdict?.kind === 'shell' && verdict.command) {
    const commandHit = entries.find(e => !isHostEntry(e) && commandMatches(verdict.command, [e]))
    if (commandHit) return { entry: commandHit, kind: 'command' }
  }
  return null
}

function flattenText(value, depth = 0) {
  if (depth > 4 || value === null || value === undefined) return ''
  if (typeof value === 'string') return value
  if (Array.isArray(value)) return value.map(v => flattenText(v, depth + 1)).filter(Boolean).join('\n')
  if (typeof value === 'object') {
    if (typeof value.text === 'string') return value.text
    if (value.content !== undefined) return flattenText(value.content, depth + 1)
  }
  return ''
}

function purposeOf(agent, limit = 600) {
  try {
    const events = agent?.session?.ownEvents?.() ?? agent?.session?.events?.() ?? []
    for (let i = events.length - 1; i >= 0; i--) {
      const evt = events[i]
      if (!evt || typeof evt !== 'object') continue
      const role = evt.role ?? evt.message?.role ?? evt.data?.role
      if (role && role !== 'assistant') continue
      const text = flattenText([evt.text, evt.message?.content, evt.data?.content, evt.content].filter(Boolean)).trim()
      if (text) return text.slice(0, limit)
    }
  } catch {  }
  return ''
}

function sessionKey(exec) {
  return String(exec.agent?.session?.id ?? exec.agent?.id ?? 'unknown')
}

async function writeAudit(entry) {
  try {
    await mkdir(AUDIT_DIR, { recursive: true })
    const file = join(AUDIT_DIR, `${new Date().toISOString().slice(0, 10)}.jsonl`)
    await appendFile(file, JSON.stringify(entry) + '\n', 'utf8')
  } catch {  }
}

async function pruneAudit(days) {
  const keep = Number(days)
  if (!Number.isFinite(keep) || keep <= 0) return
  let names
  try { names = await readdir(AUDIT_DIR) } catch { return }
  const cutoff = Date.now() - keep * 86400000
  for (const file of names) {
    const match = /^(\d{4}-\d{2}-\d{2})\.jsonl$/.exec(file)
    if (!match) continue
    const stamp = Date.parse(`${match[1]}T00:00:00Z`)
    if (Number.isFinite(stamp) && stamp < cutoff) await unlink(join(AUDIT_DIR, file)).catch(() => {})
  }
}

async function loadState() {
  try { return JSON.parse(await readFile(STATE_FILE, 'utf8')) } catch { return {} }
}

async function saveState(state) {
  try {
    await mkdir(STATE_DIR, { recursive: true })
    await writeFile(STATE_FILE, JSON.stringify(state, null, 2), 'utf8')
    return true
  } catch { return false }
}

function migrate(raw) {
  const state = { ...(raw ?? {}) }
  let changed = false
  if (!Array.isArray(state.allowlist)) { state.allowlist = Array.isArray(state.allowlist) ? state.allowlist : []; changed = true }
  const legacy = [
    ...(Array.isArray(state.autoAllowHosts) ? state.autoAllowHosts : []),
    ...(Array.isArray(state.extraNetworkTools) ? state.extraNetworkTools : []),
  ].map(item => String(item).trim()).filter(Boolean)
  for (const item of legacy) {
    if (!state.allowlist.some(existing => String(existing).toLowerCase() === item.toLowerCase())) {
      state.allowlist.push(item)
      changed = true
    }
  }
  for (const key of ['autoAllowHosts', 'extraNetworkTools', 'exemptHosts', 'hostMode', 'onHostTimeout']) {
    if (key in state) { delete state[key]; changed = true }
  }
  return { state, changed }
}

const VERSION_PROMISE = readFile(new URL('./package.json', import.meta.url), 'utf8')
  .then(text => {
    const value = JSON.parse(text)?.version
    return typeof value === 'string' && value ? value : ''
  })
  .catch(() => '')

function readJsonBody(req, limit = 64 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0
    const chunks = []
    req.on('data', chunk => {
      size += chunk.length
      if (size > limit) { req.destroy(); reject(new Error('body too large')); return }
      chunks.push(chunk)
    })
    req.on('end', () => {
      try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}) } catch (error) { reject(error) }
    })
    req.on('error', reject)
  })
}

export const _test = {
  classify, hostsIn, isPrivateHost, purposeOf, DEFAULTS, normalizePolicy,
  allowlisted, isHostEntry, hostAllowed, toolMatches, commandMatches, migrate,
}

export function apply(ctx, config) {
  let stored = {}
  let version = '0.0.0'
  let lastPrune = 0
  const ready = Promise.all([loadState(), VERSION_PROMISE]).then(async ([raw, tag]) => {
    const migrated = migrate(raw)
    stored = migrated.state
    if (migrated.changed) void saveState(stored)
    version = tag || '0.0.0'
    void pruneAudit(cfg().auditRetentionDays)
    lastPrune = Date.now()
  })
  const cfg = () => ({ ...DEFAULTS, ...(config ?? {}), ...stored })

  const grants = new Map()
  const inFlight = new Set()
  const stats = { asked: 0, allowed: 0, denied: 0 }
  let lastAgent = null

  async function judge({ tool, target, hosts, command, preview, purpose, signal, callId }) {
    let decision = 'allowed'
    let via = 'once'
    let custom = ''

    const timeoutMs = Math.max(5000, Math.min(Number(cfg().askTimeoutMs ?? 30000) || 30000, 600000))
    const autoAllow = (cfg().onTimeout ?? 'deny') === 'allow'
    const autoAction = autoAllow ? '放行' : '拒绝'
    const timer = new Promise((_, reject) => setTimeout(
      () => reject(Object.assign(new Error('timeout'), { code: 'NET_CONSENT_TIMEOUT' })),
      timeoutMs,
    ))

    try {
      const answer = await Promise.race([
        ctx.userQuestions.ask({
          agent: lastAgent ?? undefined,
          signal,
          questions: [{
            id: 'net-consent',
            header: '联网审批',
            question: `${tool} 申请联网：${target}`,
            detail: [
              purpose ? `AI 自述用途：\n${purpose}` : '模型没有先说明用途。',
              command ? `命令：\n${command.slice(0, 600)}` : '',
              preview && preview !== command ? `调用内容摘要：\n${preview}` : '',
              `${Math.round(timeoutMs / 1000)} 秒内未选择将自动${autoAction}。`,
            ].filter(Boolean).join('\n\n'),
            options: [
              { label: '放行一次', description: '只放行这一次' },
              { label: '本会话放行该目标', description: '本会话内对这些目标不再询问' },
              { label: '拒绝', description: '阻止本次联网' },
            ],
          }],
        }),
        timer,
      ])
      const item = answer?.answers?.find(a => a.id === 'net-consent') ?? answer?.answers?.[0]
      const selected = item?.selected ?? []
      custom = (item?.custom ?? '').trim()
      if (custom && selected.length === 0) { decision = 'denied'; via = 'custom' }
      else if (selected.some(label => String(label).includes('会话'))) { decision = 'allowed'; via = 'session-grant' }
      else if (selected.some(label => /^(放行一次|允许一次)/.test(String(label)))) { decision = 'allowed'; via = 'once' }
      else { decision = 'denied'; via = 'user-reject' }
    } catch (error) {
      const code = error?.code ?? ''
      decision = 'denied'
      via = code || 'error'
      if (code === 'DELEGATED_CALLER') via = 'delegated'
      if (code === 'NET_CONSENT_TIMEOUT' && autoAllow) {
        decision = 'allowed'
        via = 'timeout-allow'
      }
    }

    if (cfg().audit !== false) {
      writeAudit({
        ts: new Date().toISOString(), tool, callId: String(callId ?? ''),
        session: lastAgent ? String(lastAgent?.session?.id ?? lastAgent?.id ?? '') : '',
        hosts, command: (command ?? '').slice(0, 400),
        preview: (preview ?? '').slice(0, 400), purpose: (purpose ?? '').slice(0, 400),
        decision, via, custom: custom || undefined,
      })
      if (Date.now() - lastPrune > 3600000) {
        lastPrune = Date.now()
        void pruneAudit(cfg().auditRetentionDays)
      }
    }
    return { decision, via, custom, timeoutMs }
  }

  ctx.on('tools/pre-execute', async (exec, next) => {
    if (exec.agent) lastAgent = exec.agent

    let verdict
    try { verdict = classify(exec, cfg()) } catch { verdict = null }
    if (!verdict || !verdict.network) return next()

    const current = cfg()
    const layer = verdict.kind === 'shell' ? 'shell' : 'tool'
    const policy = normalizePolicy(layer === 'shell' ? current.shellMode : current.mode, 'ask')
    if (policy === 'allow') return next()

    const hosts = verdict.hosts ?? []
    const publicHosts = hosts.filter(h => !(current.allowLocal && isPrivateHost(h)))
    const onlyLocal = hosts.length > 0 && publicHosts.length === 0
    if (current.allowLocal && onlyLocal) return next()

    const probe = { ...verdict, tool: String(exec.name ?? '') }
    const whitelisted = allowlisted(probe, current)
    if (whitelisted) return next()

    const key = sessionKey(exec)
    const target = publicHosts.length > 0
      ? publicHosts.join(', ')
      : (layer === 'shell' ? '目的地未知（命令里没解析出主机名）' : '目的地未知')

    if (policy === 'deny') {
      stats.denied++
      if (current.audit !== false) writeAudit({
        ts: new Date().toISOString(), tool: exec.name, callId: String(exec.callId ?? ''),
        session: key, hosts: publicHosts, command: (verdict.command ?? '').slice(0, 400),
        preview: verdict.preview, decision: 'denied', via: 'policy=deny',
      })
      return { kind: 'deny', reason: `net-consent：${exec.name} 需要联网（${target}），当前策略为拒绝，已阻止。` }
    }

    const granted = grants.get(key) ?? new Set()
    if (hosts.length > 0 && publicHosts.every(h => granted.has(h))) return next()
    if (hosts.length === 0 && granted.has('*')) return next()

    if (!ctx.userQuestions) {
      stats.denied++
      return { kind: 'deny', reason: 'net-consent：审批服务不可用，已按失败关闭原则阻止本次联网。' }
    }

    const askId = String(exec.callId ?? `${exec.name}-${Date.now()}`)
    if (inFlight.has(askId)) return { kind: 'deny', reason: 'net-consent：同一次调用重复进入审批，已阻止。' }
    inFlight.add(askId)

    let outcome
    try {
      stats.asked++
      outcome = await judge({
        tool: String(exec.name),
        target,
        hosts: publicHosts,
        command: verdict.command,
        preview: verdict.preview,
        purpose: current.purposes === false ? '' : purposeOf(exec.agent),
        signal: exec.signal,
        callId: exec.callId,
      })
    } finally {
      inFlight.delete(askId)
    }

    if (outcome.decision === 'allowed') {
      stats.allowed++
      if (outcome.via === 'session-grant') {
        if (hosts.length === 0) granted.add('*')
        for (const h of publicHosts) granted.add(h)
        grants.set(key, granted)
      }
      return next()
    }

    stats.denied++
    if (outcome.via === 'custom') {
      return { kind: 'deny', reason: `net-consent：用户没有批准这次联网，而是补充说明：「${outcome.custom}」。请按该说明调整做法；若仍需联网，会被再次询问。` }
    }
    if (outcome.via === 'delegated') {
      return { kind: 'deny', reason: 'net-consent：子代理内无法弹审批（DSH 禁止子代理向用户提问），已阻止。请让主代理来做联网操作。' }
    }
    if (outcome.via === 'NET_CONSENT_TIMEOUT') {
      return { kind: 'deny', reason: `net-consent：等待审批超时（${Math.round(outcome.timeoutMs / 1000)}s），已阻止本次联网。` }
    }
    if (outcome.via === 'ASK_ABORTED') {
      return { kind: 'deny', reason: 'net-consent：审批被取消，本次联网未执行。' }
    }
    if (outcome.via === 'user-reject') {
      return { kind: 'deny', reason: `net-consent：用户拒绝了对 ${target} 的联网访问。不要重试同一目标，除非用户明确要求。` }
    }
    return { kind: 'deny', reason: `net-consent：审批未通过（${outcome.via}），已阻止本次联网。` }
  })

  const snapshot = () => {
    const current = cfg()
    return {
      mode: normalizePolicy(current.mode, 'ask'),
      shellMode: normalizePolicy(current.shellMode, 'ask'),
      allowLocal: current.allowLocal !== false,
      askTimeoutMs: Number(current.askTimeoutMs ?? 30000),
      onTimeout: current.onTimeout === 'allow' ? 'allow' : 'deny',
      audit: current.audit !== false,
      auditRetentionDays: Number(current.auditRetentionDays ?? 30),
      allowlist: (current.allowlist ?? []).map(String),
      purposes: current.purposes !== false,
      stats: { asked: stats.asked, allowed: stats.allowed, denied: stats.denied },
      version,
    }
  }

  const ROUTE_KEY = Symbol.for('dsh-net-consent.routes')
  const ROUTE_BASE = '/net-consent'

  const writeDebug = async (line) => {
    try {
      await mkdir(STATE_DIR, { recursive: true })
      await appendFile(join(STATE_DIR, 'debug.log'), `${new Date().toISOString()} ${line}\n`)
    } catch {  }
  }

  const routeHandler = async (req, res) => {
    const url = new URL(req.url ?? '/', 'http://localhost')
    const send = (status, payload) => {
      const body = JSON.stringify(payload)
      res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' })
      res.end(body)
    }
    if (url.pathname !== `${ROUTE_BASE}/state`) return send(404, { error: 'not found' })
    await ready

    if (req.method === 'GET' || req.method === 'HEAD') return send(200, snapshot())

    if (req.method === 'POST') {
      let patch
      try { patch = await readJsonBody(req) } catch { return send(400, { error: 'bad json' }) }
      const next = {}
      for (const key of WRITABLE) if (key in (patch ?? {})) next[key] = patch[key]
      for (const key of ['mode', 'shellMode']) {
        if (next[key] === undefined) continue
        const value = LEGACY_POLICY[next[key]] ?? next[key]
        if (POLICIES.includes(value)) next[key] = value
        else delete next[key]
      }
      if (next.allowLocal !== undefined) next.allowLocal = next.allowLocal !== false
      if (next.audit !== undefined) next.audit = next.audit !== false
      if (next.purposes !== undefined) next.purposes = next.purposes !== false
      if (next.allowlist !== undefined) {
        if (!Array.isArray(next.allowlist)) delete next.allowlist
        else next.allowlist = [...new Set(next.allowlist.map(String).map(s => s.trim()).filter(Boolean))]
      }
      if (next.askTimeoutMs !== undefined) {
        const ms = Number(next.askTimeoutMs)
        if (Number.isFinite(ms) && ms >= 5000 && ms <= 600000) next.askTimeoutMs = Math.round(ms)
        else delete next.askTimeoutMs
      }
      if (next.auditRetentionDays !== undefined) {
        const days = Math.round(Number(next.auditRetentionDays))
        if (Number.isFinite(days) && days >= 0 && days <= 3650) next.auditRetentionDays = days
        else delete next.auditRetentionDays
      }
      if (next.onTimeout !== undefined) {
        const value = LEGACY_POLICY[next.onTimeout] ?? next.onTimeout
        if (value === 'allow' || value === 'deny') next.onTimeout = value
        else delete next.onTimeout
      }
      stored = { ...stored, ...next }
      const ok = await saveState(stored)
      void pruneAudit(cfg().auditRetentionDays)
      return send(ok ? 200 : 500, { ...snapshot(), saved: ok })
    }
    return send(405, { error: 'method not allowed' })
  }

  try {
    const previous = globalThis[ROUTE_KEY]
    if (Array.isArray(previous)) {
      for (const dispose of previous) { try { dispose() } catch {  } }
    }
    const registered = []
    if (typeof ctx.webServer?.register === 'function') {
      registered.push(ctx.webServer.register({ kind: 'exact', path: `${ROUTE_BASE}/state`, handler: routeHandler }))
      registered.push(ctx.webServer.register({ kind: 'prefix', path: ROUTE_BASE, handler: routeHandler }))
      globalThis[ROUTE_KEY] = registered
      void writeDebug(`routes registered: ${ROUTE_BASE}/state (exact) + ${ROUTE_BASE} (prefix)`)
      ctx.on('dispose', () => {
        for (const dispose of registered) { try { dispose() } catch {  } }
        if (globalThis[ROUTE_KEY] === registered) globalThis[ROUTE_KEY] = undefined
      })
    } else {
      void writeDebug(`route skipped: typeof webServer=${typeof ctx.webServer} typeof register=${typeof ctx.webServer?.register}`)
    }
  } catch (error) {
    void writeDebug(`route registration failed: ${error?.stack ?? String(error)}`)
  }
}
