window.__ModuleLoader__.load({
  id: 'dsh-net-consent',
  factory(require) {
    const React = require('react')
    const h = React.createElement
    const { useState, useEffect, useCallback } = React

    const STATE_URL = '/net-consent/state'

    const store = {
      value: null,
      error: null,
      listeners: new Set(),
      emit() { for (const fn of this.listeners) fn(this.value) },
      subscribe(fn) { this.listeners.add(fn); return () => this.listeners.delete(fn) },
      async load() {
        try {
          const res = await fetch(STATE_URL, { headers: { accept: 'application/json' } })
          if (!res.ok) throw new Error('HTTP ' + res.status)
          this.value = await res.json()
          this.error = null
        } catch (error) { this.error = String(error && error.message || error) }
        this.emit()
      },
      async patch(patch) {
        const previous = this.value
        this.value = { ...(this.value || {}), ...patch }
        this.emit()
        try {
          const res = await fetch(STATE_URL, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify(patch),
          })
          if (!res.ok) throw new Error('HTTP ' + res.status)
          this.value = await res.json()
          this.error = null
        } catch (error) {
          this.value = previous
          this.error = String(error && error.message || error)
        }
        this.emit()
      },
    }
    store.load()
    setInterval(() => store.load(), 5000)

    function useStore() {
      const [value, setValue] = useState(store.value)
      useEffect(() => {
        const off = store.subscribe(next => setValue(next))
        if (!store.value) store.load()
        return off
      }, [])
      return [value, store.error]
    }

    const POLICY = [['allow', '放行'], ['ask', '每次询问'], ['deny', '拒绝']]
    const policyOf = value => (value === 'allow' || value === 'deny' ? value : 'ask')
    const labelOf = value => (POLICY.find(([key]) => key === policyOf(value)) ?? POLICY[1])[1]

    const TIMEOUTS = [
      ['15000', '15 秒'], ['30000', '30 秒'], ['60000', '1 分钟'],
      ['180000', '3 分钟'], ['600000', '10 分钟'],
    ]
    const TIMEOUT_ACTIONS = [['deny', '自动拒绝'], ['allow', '自动放行']]
    const RETENTIONS = [['7', '7 天'], ['30', '30 天'], ['90', '90 天'], ['0', '永久保留']]

    const S = {
      pill: (on) => ({
        display: 'inline-flex', alignItems: 'center', gap: 6,
        height: 28, padding: '0 10px', borderRadius: 14, cursor: 'pointer',
        border: '1px solid ' + (on ? 'rgba(64,158,255,0.55)' : 'rgba(128,128,128,0.35)'),
        background: on ? 'rgba(64,158,255,0.14)' : 'transparent',
        color: on ? 'rgb(64,158,255)' : 'inherit',
        fontSize: 12, lineHeight: '26px', whiteSpace: 'nowrap', userSelect: 'none',
        fontFamily: 'inherit',
      }),
      dot: (on) => ({
        width: 7, height: 7, borderRadius: 4,
        background: on ? 'rgb(64,158,255)' : 'rgba(128,128,128,0.6)',
      }),
      page: { padding: '24px 28px', maxWidth: 680, fontSize: 13, lineHeight: 1.6 },
      h1: { fontSize: 16, fontWeight: 600, margin: '0 0 4px' },
      lead: { opacity: 0.65, margin: '0 0 20px' },
      group: { margin: '0 0 22px' },
      groupTitle: { fontSize: 12, fontWeight: 600, opacity: 0.55, letterSpacing: '0.04em', margin: '0 0 8px' },
      row: {
        display: 'flex', alignItems: 'flex-start', gap: 10,
        padding: '9px 0', borderTop: '1px solid rgba(128,128,128,0.16)',
      },
      rowText: { flex: 1, minWidth: 0 },
      rowName: { fontSize: 13 },
      rowHint: { fontSize: 12, opacity: 0.55, marginTop: 2 },
      select: {
        fontSize: 12, padding: '3px 6px', borderRadius: 6, fontFamily: 'inherit',
        border: '1px solid rgba(128,128,128,0.35)', background: 'transparent', color: 'inherit',
      },
      textarea: {
        fontSize: 12, padding: '6px 8px', borderRadius: 6, fontFamily: 'inherit',
        border: '1px solid rgba(128,128,128,0.35)', background: 'transparent', color: 'inherit',
        width: '100%', minHeight: 88, resize: 'vertical', lineHeight: 1.6,
      },
      footer: {
        display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', gap: 12,
        fontSize: 12, opacity: 0.55, marginTop: 26,
      },
      warn: { fontSize: 12, color: 'rgb(230,160,60)', marginTop: 8 },
    }

    function ConsentToggle() {
      const [value, error] = useStore()
      const mode = policyOf(value?.mode)
      const shellMode = policyOf(value?.shellMode)
      const on = mode !== 'allow' || shellMode !== 'allow'
      const title = value
        ? `工具 ${labelOf(mode)} · 命令行 ${labelOf(shellMode)}；本次已询问 ${value?.stats?.asked ?? 0} 次。点击${on ? '关闭' : '开启'}联网审查。`
        : (error || '正在读取联网审查状态…')
      const flip = useCallback(() => {
        const next = on ? 'allow' : 'ask'
        store.patch({ mode: next, shellMode: next })
      }, [on])
      return h('button', {
        type: 'button',
        onClick: flip,
        title,
        style: S.pill(on),
        'aria-pressed': on,
      },
        h('span', { style: S.dot(on) }),
        h('span', null, '联网审查'),
        h('span', { style: { opacity: on ? 0.85 : 0.55 } }, on ? '开' : '关'),
      )
    }

    function Row({ name, hint, children }) {
      return h('div', { style: S.row },
        h('div', { style: S.rowText },
          h('div', { style: S.rowName }, name),
          hint ? h('div', { style: S.rowHint }, hint) : null,
        ),
        h('div', { style: { flex: 'none', paddingTop: 1 } }, children),
      )
    }

    function Select({ value, options, onChange }) {
      return h('select', {
        style: S.select,
        value,
        onChange: event => onChange(event.target.value),
      }, options.map(([key, label]) => h('option', { key, value: key }, label)))
    }

    function Check({ value, onChange }) {
      return h('input', {
        type: 'checkbox',
        checked: !!value,
        onChange: event => onChange(event.target.checked),
      })
    }

    function PolicySelect({ value, onChange }) {
      return h(Select, { value: policyOf(value), options: POLICY, onChange })
    }

    function NetConsentSection() {
      const [value, error] = useStore()
      if (!value) {
        return h('div', { style: S.page },
          h('div', { style: S.h1 }, '联网审查'),
          h('div', { style: S.lead }, error ? '读不到状态：' + error : '正在读取…'),
        )
      }
      const set = patch => store.patch(patch)
      const stats = value.stats ?? {}
      return h('div', { style: S.page },
        h('div', { style: S.h1 }, '联网审查'),

        h('div', { style: S.group },
          h('div', { style: S.groupTitle }, '联网动作'),
          h('div', null,
            h(Row, { name: '工具', hint: 'web_fetch、web_search、浏览器工具、带 URL 的第三方工具' },
              h(PolicySelect, { value: value.mode, onChange: next => set({ mode: next }) })),
            h(Row, { name: '命令行', hint: 'curl、wget、git clone、pnpm install 等' },
              h(PolicySelect, { value: value.shellMode, onChange: next => set({ shellMode: next }) })),
            h(Row, { name: '本机与局域网地址免询问', hint: '127.0.0.1、192.168.x 等' },
              h(Check, { value: value.allowLocal !== false, onChange: next => set({ allowLocal: next }) })),
          )),

        h('div', { style: S.group },
          h('div', { style: S.groupTitle }, '白名单'),
          h('div', null,
            h(Row, { name: '免问条目', hint: '一行一条：工具名、命令名、域名或 IP。例：web_fetch、curl、example.com、*.example.com、8.8.8.8' },
              h('textarea', {
                defaultValue: (value.allowlist || []).join('\n'),
                placeholder: 'web_fetch\ncurl\nexample.com\n*.example.com\n8.8.8.8',
                onBlur: event => set({
                  allowlist: event.target.value.split(/[\n,，]/).map(s => s.trim()).filter(Boolean),
                }),
                style: S.textarea,
              })),
          )),

        h('div', { style: S.group },
          h('div', { style: S.groupTitle }, '审批卡片'),
          h('div', null,
            h(Row, { name: '等待时间', hint: '卡片上写明本次时限' },
              h(Select, {
                value: String(value.askTimeoutMs ?? 30000),
                options: TIMEOUTS,
                onChange: next => set({ askTimeoutMs: Number(next) }),
              })),
            h(Row, { name: '超时后', hint: '倒计时结束仍未选择时执行' },
              h(Select, {
                value: value.onTimeout === 'allow' ? 'allow' : 'deny',
                options: TIMEOUT_ACTIONS,
                onChange: next => set({ onTimeout: next }),
              })),
            h(Row, { name: '显示 AI 用途自述', hint: '卡片展示模型联网前的说明' },
              h(Check, { value: value.purposes !== false, onChange: next => set({ purposes: next }) })),
          )),

        h('div', { style: S.group },
          h('div', { style: S.groupTitle }, '审计'),
          h('div', null,
            h(Row, { name: '记录审计日志', hint: '~/.dsh/net-consent/audit/，按天分文件' },
              h(Check, { value: value.audit !== false, onChange: next => set({ audit: next }) })),
            h(Row, { name: '保留天数', hint: '过期文件自动清理' },
              h(Select, {
                value: String(value.auditRetentionDays ?? 30),
                options: RETENTIONS,
                onChange: next => set({ auditRetentionDays: Number(next) }),
              })),
          )),

        error ? h('div', { style: S.warn }, '上次保存失败：' + error) : null,

        h('div', { style: S.footer },
          h('span', null,
            `本次运行：询问 ${stats.asked ?? 0} 次，放行 ${stats.allowed ?? 0} 次，拒绝 ${stats.denied ?? 0} 次。`),
          h('span', null, value.version ? 'v' + value.version : ''),
        ),
      )
    }

    return {
      inject: ['slots'],
      apply(ctx) {
        ctx.slots.inject('conversation.input.right', () => ctx.slots.register(
          { name: 'conversation.input.right', id: 'net-consent-toggle', order: 10 },
          ConsentToggle,
        ))
        ctx.slots.inject('settings.section', () => ctx.slots.register(
          { name: 'settings.section', id: 'net-consent', order: 50, label: '联网审查' },
          NetConsentSection,
        ))
      },
    }
  },
})
