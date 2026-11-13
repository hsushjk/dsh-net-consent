# dsh-net-consent

[![DSH 插件](https://img.shields.io/badge/DeepSeek%20Harness%20Plugin-0078d6)]()
[![平台](https://img.shields.io/badge/Linux-Windows-fcc624)]()

联网闸门：会话里 Agent 发起的联网，都要用户来批准

## 使用场景

需要手动控制联网行为/流量成本。弱网/漫游/卫星/海事

> 这是一套**审批/拦截**工具，不是流量计数器。它只审查不统计。有统计观测需求请使用[dsh-traffic-statistics](https://github.com/hsushjk/dsh-traffic-statistics)

## 审什么

会话自己发起的：

| 层 | 覆盖 | 策略键 |
|---|---|---|
| 工具 | `web_fetch`、`web_search`、浏览器 / Playwright 类工具、带 http(s) URL 的第三方插件工具 | `mode` |
| 命令行 | `curl`、`wget`、`ssh`、`scp`、`rsync`、`git clone`、`pnpm install`、`pip install`、`apt`、`snap refresh`、`pacman -S`、`svn checkout` … | `shellMode` |

这些除外：聊天请求、插件市场与插件详情的后台拉取、更新检查、遥测。这些不经过会话工具，也就不在插件的职责里。插件不包 `globalThis.fetch`，不改 `node:http(s).request`，只挂一个 `tools/pre-execute` 监听。

## 策略

策略为 **放行 / 每次询问 / 拒绝**，工具层与命令行层各有一档（`mode` / `shellMode`）。

- `allow`：不弹卡片。
- `ask`：弹卡片（默认）。
- `deny`：直接阻止，不弹卡片。

`deny` 优先于「本会话放行」；本机 / 局域网地址与白名单命中项先放行。

## 审批卡片

三个选项：`放行一次`、`本会话放行该目标`、`拒绝`。点「其它」填文字则默认拒绝，并把你的原话回给模型让它改路线。

- 卡片包括 AI 的用途自述（可关），命令行走命令原文，其它工具走调用参数摘要。
- 卡片末尾写明本次时限与超时动作，例如「30 秒内未选择将自动拒绝。」等待时间与超时动作（自动拒绝 / 自动放行）都在设置里改。
- 子代理内无法弹卡片（DSH 禁止子代理向用户提问），按拒绝处理并提示让主代理来做。

## 白名单

一条只用一种写法，命中即免问：

| 写法 | 例子 | 命中方式 |
|---|---|---|
| 工具名 | `web_fetch`、`browser_*` | 工具名全等；结尾 `*` 作前缀通配 |
| 命令名 | `curl`、`git`、`pnpm` | 在命令文本里按整词匹配 |
| 域名 | `example.com`、`*.example.com` | 该次调用的主机全部命中才放行 |
| IP | `8.8.8.8`、`::1` | 精确匹配 |

白名单是显式例外表，先于 `deny` 策略生效。

## 配置

`cordis.patch.yml` 里 `net-consent` 行的 `config:`：

| 键 | 默认 | 含义 |
|---|---|---|
| `mode` | `ask` | 工具层：`allow` / `ask` / `deny` |
| `shellMode` | `ask` | 命令行联网动词：`allow` / `ask` / `deny` |
| `allowLocal` | `true` | 回环与局域网地址免问 |
| `askTimeoutMs` | `30000` | 等用户回答的超时（5s–10min） |
| `onTimeout` | `deny` | 超时后：`deny` 自动拒绝 / `allow` 自动放行 |
| `audit` | `true` | 写审计 jsonl |
| `auditRetentionDays` | `30` | 审计保留天数，`0` = 永久 |
| `allowlist` | `[]` | 工具 / 命令 / 域名 / IP，见上表 |
| `purposes` | `true` | 卡片展示模型自述用途 |
| `internalTools` | 一长串只读工具 | 完全不看的工具（UI 不可改） |

## 审计

每次判定写一行 JSON 到 `~/.dsh/net-consent/audit/YYYY-MM-DD.jsonl`，`via` 字段区分放行 / 拒绝原因（`once`、`session-grant`、`user-reject`、`policy=deny`、`timeout-allow`、`NET_CONSENT_TIMEOUT` …）。超过保留天数的按天文件在启动时与写入后自动清理。