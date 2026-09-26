# Changelog

## 0.2.9

- **Fix: malformed peer `x25519` no longer kills the host process**
  (flutter_agent_harness #988). Presence/agent-info keys are
  peer-controlled strings; `_tryDhPubkey` now decodes them tolerantly
  (trim, quote-strip, `%3D` percent-decode, base64url alphabet,
  re-pad). Unpadded 43-char JS-client keys are RECOVERED (E2E with the
  peer keeps working); anything not 32 decodable bytes degrades to
  `dhPublicKey: null` + an `onNotice` — the roster entry survives.
  Non-map / agentId-less roster entries are skipped with a notice.
- **Fix: pre-welcome drops no longer escape as 'Bad state: connection
  closed'** (the second #988 crash). A socket dying while the hello was
  still signing made `_abandon` complete the welcome completer before
  anyone awaited it — an unhandled zone error per reconnect attempt,
  with an empty stack. The completer's future now carries `ignore()`.
- Frame-pump guard: any single inbound frame handler throw lands in
  `onNotice` ('malformed hub frame ignored') — one bad frame from a
  hostile/buggy hub never takes the connection or the process down.

## 0.2.8

- **Renamed and published as `fa_hub_client`** (the `fah_hub_client`
  package name is owned by a different pub.dev account; same code, MIT
  license preserved, original copyright retained).
- **Critical CPU fix:** `HubClient.defaultBackoff` clamped the attempt
  BEFORE shifting — `1 << (attempt - 1)` overflows 64-bit int semantics
  (attempt 64 → negative, attempt 65+ → 0), so the 30 s cap never applied
  past the 64th failed reconnect and the loop degraded into a tight spin
  reconnecting to a dead hub at full speed forever. Observed live:
  `_reconnectAttempt = 69,730,601` with every idle `fa` process burning
  ~60–90% CPU (plus `kernel_task`/`xprotectd` amplification from the
  socket churn). Every reconnect now waits ≥1 s, capped at 30 s, no
  matter how long the hub stays down.

## 0.2.4

- Additive liveness surface for the messaging fabric. `AgentInfo.lastSeen`
  (DateTime?, null on legacy hubs — never treat null as stale) parses the
  hub roster's activity-accurate `lastSeen` (dap v0.3.1+; bumped per
  authenticated inbound frame instead of frozen at connect time).
  `MailboxEntry.isLive` (bool?) + `MailboxEntry.lastActivity` (DateTime?)
  carry SOURCE-DEFINED semantics — a hub-backed repository fills them from
  the roster (online flag + hub lastSeen), a file-backed repository from
  mailbox mtimes; NEVER compare across sources; null = unknown = never
  hidden. `HubMessagingRepository.directory()` populates both so downstream
  fabrics (flutter_agent_harness agent_directory) consume one authoritative
  type instead of patching a local copy.

## 0.2.3

- 401 self-recovery for a stale persisted client secret (live incident
  2026-09-01: a hub restart wiped the server-side secrets, so every
  previously enrolled client 401-looped — the cached `clientSecret`
  won precedence over `DAP_MASTER_SECRET` and the rejection was
  fatal). `resolveDapClientSecret` now also reports WHERE the dial
  credential came from (`DapSecretSource`: env / config / master /
  none) and echoes the raw master secret. On a pre-upgrade 401,
  `HubClient` escalates EXACTLY ONCE when — and only when — the
  rejected secret came from `~/.dap/config.json` AND a master secret
  is available: it drops the provably dead cache entry from the
  persisted config, dials again in enroll-mode (the re-enroll binds to
  the same hello name — key files and agent identity untouched), and
  persists the newly issued secret through the same path as a first
  enroll. A second 401 is fatal with the frozen cross-adapter hint;
  env-sourced secrets (`DAP_CLIENT_SECRET` = explicit user intent)
  and master-less setups keep today's hard fail. No retry loops, no
  new env vars.

## 0.2.2

- Closed 0.2.1's residual first-query steal window: `HubClient` now
  fires a welcome-time warm-up `presence_query` on EVERY fresh
  connection — a throwaway whose only job is to make the hub echo
  `replyTo` and arm the echo-seen latch BEFORE any consumer query, so
  the startup join self-echo (a replyTo-less broadcast) can no longer
  drain the first `peers()` with a one-agent roster. Up to 2 retries
  while the latch is still unarmed; legacy hubs (answers without
  `replyTo`) leave the latch unarmed and keep the one-completes-all
  path; a reconnect re-runs the warm-up (a no-op once armed — the
  latch stays client-lifetime). The warm-up result is discarded and
  send failures clean up their waiter (the whois pattern — a
  listener-less pending completer could surface as an unhandled
  async error at teardown). Value contract for concurrent user
  queries unchanged.

## 0.2.1

- Fixed the owner-reported presence race (bug 2026-08-31, FA "BUG 5"):
  an UNSOLICITED `presence` broadcast completing a pending
  `presence_query` waiter made `peers()` return ONLY the broadcast's
  agent instead of the answer's roster. `presenceQuery()` now sends a
  frame id; per the hub `replyTo` contract (additive, docs/protocol.md
  §presence) an ANSWER echoes that id in `replyTo` and completes only
  the matching waiters — concurrent queries keep their own ids. On a
  hub known to echo, replyTo-less `presence` frames are broadcasts and
  never complete waiters. Legacy hubs (no echo) keep the 0.1.4
  one-completes-all answer path — old deployments keep working; the
  residual window (a broadcast racing the FIRST query to a new hub,
  before any echo is seen) is documented on `HubClient._onPresence`.

## 0.2.0

- BREAKING (owner decision 2026-08-31): `peers()` takes NO parameters —
  the `includeOffline` flag is gone. It now ALWAYS returns online-only
  agents and marks our own entry with `AgentInfo.self == true` (self
  stays in the list, not excluded). `AgentInfo` gains the `self` field
  (default false); raw `presenceQuery()`/`whois` entries are unchanged.
  `HubPlugin.peers` and `HubMessagingRepository.peers` aligned to the
  same no-flag shape.

## 0.1.4

- Request doors (`whois`/`flush`/`presenceQuery`) now fan out to waiter
  LISTS: concurrent callers all complete with the answer. Previously a
  second caller clobbered the single completer and ORPHANED the first —
  the live hang was the 15s PendingInvites presence poller racing a
  tool's `peers()`, and an inbound-DM sender whois racing a `sendDm` to
  the same peer. 0.1.3's request timeouts and error-frame completion are
  unchanged (each caller keeps its own 10s cap; genuine hub silence
  still fails loudly).
- Ported the FA SilentHub acceptance suite (`test/silent_hub_test.dart`):
  5 scenarios — silent `presence_query`, silent `whois`, error-answered
  `presence_query`, and the two clobber races (poller-vs-tool
  `presenceQuery`, whois-vs-whois on one target) — asserting every
  request COMPLETES within 3s; with a healthy hub answering once, both
  concurrent callers must receive the answer.

## 0.1.3

- Request timeouts on `whois`/`flush`/`presenceQuery`
  (`HubClient.requestTimeout`, default 10 s): a hub that never answers
  no longer hangs the caller forever — the request fails loudly ("hub
  did not answer <op> …") and the pending slot is released so a late
  answer cannot complete a dead request.
- Hub `error` frames now also complete pending flush/presence requests
  (mirroring disconnect handling); previously they only surfaced on the
  `errors` stream and left the caller waiting — the CLI no longer hangs
  when the hub answers with an error.

## 0.1.2

- Ported FA review fixes (db65522): `HubIdentity.load` warns loudly and
  returns false when the key file cannot be locked to mode 0600
  (injectable `setPrivateMode`/`warn`); HKDF honors the RFC 5869
  255-block cap; `HubPlugin.isDefaultUrl` lets hosts keep zero-config
  default-hub connect failures quiet.
- Whole-tree `dart format`; CI gained a `dart format` gate.

## 0.1.1


- Enrollment auth: first connect enrolls via `DAP_MASTER_SECRET`; the
  hub-issued client secret is persisted in `~/.dap/config.json`.
- `HubPlugin.inviteTo` / `connectTo`: dap_invite and dap_connect, including
  pending invites armed for offline names and auto-delivered on presence.
- WebSocket keepalive so long-lived hub connections survive idle periods.
- Zero-config startup: settings resolve from env (`DAP_HUB_URL`,
  `DAP_AGENT_NAME`, `DAP_KEY_PATH`, `DAP_CHANNELS_FILE`) >
  `~/.dap/config.json` > defaults; identity auto-created at
  `~/.dap/keys/fah/<name>.key`.

## 0.2.5

- feat(plugin): public sendToChannel — channel-send parity with omp's dap_send

## 0.2.6

- chore: apply dart format
- fix: plugin inert without DAP_MASTER_SECRET

## 0.2.7

- fix(ci): publish to pub.dev from tag refs via workflow_dispatch

## Unreleased
