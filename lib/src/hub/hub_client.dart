/// DAP/1 WebSocket hub client (docs/protocol.md): signed hello handshake,
/// E2E-encrypted channel/DM sends, whois-before-first-DM, flush after
/// welcome, reconnect with exponential backoff (1 s → 30 s, reset after
/// a successful welcome), and pending by-name invites auto-delivered
/// once the invitee comes online ([PendingInvites]).
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:cryptography/cryptography.dart';

import 'canonical.dart';
import 'channels.dart';
import 'dap_settings.dart';
import 'hub_config.dart';
import 'identity.dart';
import 'payload_crypto.dart';

/// A hub `error` frame.
class HubError implements Exception {
  HubError(this.code, this.msg);

  final String code;
  final String msg;

  @override
  String toString() => 'HubError($code): $msg';
}

/// A channel join the hub denied (issue #1016). Master-gated hubs reject
/// client-secret joins of unknown channels with `access_denied`
/// (msg prefix "channel creation requires"); ACL rejections carry the
/// same code with msg "pubkey not on channel ACL" — [msg] is the
/// discriminator, the wire never echoes the channel id.
class JoinDenied {
  JoinDenied(this.channel, this.code, this.msg);

  /// The channel the client attempted to join.
  final String channel;

  /// Always `access_denied` today; kept for forward compatibility.
  final String code;

  /// The hub's message (creation gate vs ACL).
  final String msg;

  @override
  String toString() => 'JoinDenied($channel): $code $msg';
}

/// Frozen cross-adapter text for a hub bearer rejection (HTTP 401 before
/// the websocket upgrade) — byte-identical in every DAP adapter; the hub
/// answers `unauthorized` for a missing/unknown secret.
const String unauthorizedMsg = 'hub rejected connection (HTTP 401): '
    'set DAP_MASTER_SECRET to enroll, or DAP_CLIENT_SECRET / config '
    'clientSecret to connect';

/// Peer directory entry returned by whois/presence.
class AgentInfo {
  AgentInfo({
    required this.agentId,
    required this.online,
    this.name,
    this.signingPubkeyB64,
    this.dhPublicKey,
    this.self = false,
    this.lastSeen,
  });

  final String agentId;
  final String? name;
  final bool online;
  final String? signingPubkeyB64;

  /// Peer X25519 public key for payload E2E (the hello `x25519` field,
  /// echoed by `agent_info`).
  final SimplePublicKey? dhPublicKey;

  /// True when this entry is OUR own agent (only [HubClient.peers]
  /// marks it); raw presence/whois entries are always false.
  final bool self;

  /// Hub-reported last authenticated inbound frame time (v0.3.1+ hubs;
  /// activity-accurate). Null on legacy hubs — never treat null as stale.
  final DateTime? lastSeen;

  /// Copy of this entry flagged as our own ([self] = true).
  AgentInfo asSelf() => AgentInfo(
        agentId: agentId,
        name: name,
        online: online,
        signingPubkeyB64: signingPubkeyB64,
        dhPublicKey: dhPublicKey,
        self: true,
        lastSeen: lastSeen,
      );
}

/// Connection snapshot for the `dap_status` tool: who we are, where we
/// are connected, what we can send to, and how the handshake is going.
class HubStatus {
  const HubStatus({
    required this.connected,
    required this.agentId,
    required this.name,
    required this.url,
    required this.channels,
    required this.welcomes,
    required this.hellos,
  });

  final bool connected;
  final String? agentId;
  final String? name;
  final String? url;

  /// Names of every channel we hold a key for (store ∪ explicit config).
  final List<String> channels;

  /// Successful handshakes (hub `welcome` frames received).
  final int welcomes;

  /// Connection attempts — one signed `hello` sent per attempt.
  final int hellos;
}

/// One inbound `msg` frame: decrypted when a key is available.
class InboundMessage {
  InboundMessage({
    required this.id,
    required this.from,
    required this.ts,
    this.channel,
    this.to,
    this.plaintext,
  });

  final String id;
  final String from;
  final int ts;
  final String? channel;
  final String? to;

  /// Null when no key is configured to decrypt (payload still delivered).
  final String? plaintext;
}

/// dap_connect result: the connection now in force (the new welcome's
/// agentId, the normalized url, the display name, every joinable room).
typedef DapConnection = ({
  bool ok,
  String url,
  String? name,
  String agentId,
  List<String> channels,
});

/// dap_invite result: `ok: false, error` is an honest failure (not
/// connected, ambiguous name, DM failure); otherwise the chankey DM went
/// out immediately (`pending: false`) or the invite was armed for a user
/// not yet online (`pending: true` — delivered automatically when they
/// connect; [connectLine] is the paste-ready line for the invited user).
typedef InviteResult = ({
  bool ok,
  String channel,
  String to,
  bool pending,
  String? connectLine,
  String? error,
});

/// One pending `presence_query` caller: the frame id sent with the query
/// (`{"op":"presence_query","id":...}`) and the completer that the answer
/// — the `presence` frame echoing that id in `replyTo` — completes.
typedef _PresenceWaiter = ({
  String requestId,
  Completer<List<AgentInfo>> completer,
});

class HubClient {
  HubClient({
    required HubConfig config,
    required HubIdentity identity,
    String? clientSecret,
    bool enroll = false,
    DapSecretSource secretSource = DapSecretSource.env,
    String? masterSecret,
    this.configFile,
    this.channelStore,
    this.onNotice,
    Duration Function(int attempt)? backoff,
    this.pingInterval = const Duration(seconds: 20),
    this.requestTimeout = HubClient.defaultRequestTimeout,
  })  : _config = config,
        _identity = identity,
        _clientSecret = clientSecret,
        _enroll = enroll,
        _secretSource = secretSource,
        _masterSecret = masterSecret,
        backoff = backoff ?? HubClient.defaultBackoff;
  HubConfig _config;

  /// Bearer token for the hub dial (see [resolveDapClientSecret]): a
  /// hub-issued client secret, or the master secret while [_enroll].
  /// Replaced by the hub-issued secret after a successful enroll — later
  /// dials (reconnects included) authenticate with it.
  String? _clientSecret;

  /// True while [_clientSecret] is a master secret awaiting enrollment:
  /// the `{"t":"enroll"}` frame goes out right after each hello until the
  /// hub answers `enrolled`.
  bool _enroll;

  /// Where the dial secret came from ([DapSecretSource]): an `env`
  /// secret is explicit user intent (a 401 hard-fails), a `config`
  /// secret is a persisted cache the 401 path may drop and re-enroll
  /// once ([_masterSecret] permitting).
  DapSecretSource _secretSource;

  /// Raw `DAP_MASTER_SECRET` kept for the one-shot stale-secret
  /// re-enroll; null disables the escalation.
  final String? _masterSecret;

  /// Set once the stale-config-secret 401 escalation has run — exactly
  /// one retry per client, never a loop.
  bool _reenrolled = false;

  /// `~/.dap/config.json` (or `DAP_CONFIG_FILE`): where the hub-issued
  /// client secret is persisted ([persistDapConfig]). Null skips
  /// persistence.
  final String? configFile;

  /// Short user-facing notices (`enrolled: client secret persisted`) —
  /// the host wires this to its terminal; the secret is never logged.
  final void Function(String notice)? onNotice;

  /// Where to connect (swapped by [retarget]).
  HubConfig get config => _config;

  HubIdentity _identity;

  /// Who we are (swapped by [retarget]; a new identity = new agentId).
  HubIdentity get identity => _identity;

  /// Zero-config channel-key lifecycle (auto-keygen on first send, invite
  /// accept, auto-join). Null keeps the explicit-config-only behavior:
  /// unknown channels fail honestly with [ArgumentError].
  final ChannelStore? channelStore;

  final Duration Function(int attempt) backoff;

  /// Client keepalive interval. Native mechanism: dart:io WebSocket
  /// auto-pings the hub every [pingInterval] and closes the socket when the
  /// pong does not come back in time — which drops us into the reconnect
  /// loop below (re-hello → flush → hold) before a user send buffers into a
  /// half-open corpse. Null disables it.
  final Duration? pingInterval;

  /// Per-request cap for whois/flush/presenceQuery: a hub that never
  /// answers a request door fails it loudly after [requestTimeout]
  /// instead of parking the caller forever. Injectable — tests use a
  /// short one.
  final Duration requestTimeout;

  WebSocket? _ws;
  StreamSubscription? _subscription;
  bool _closing = false;

  /// Reconnect-loop generation: bumping it ([retarget]) retires any loop
  /// still parked in backoff so it cannot double-connect alongside the
  /// fresh one.
  int _epoch = 0;
  int _reconnectAttempt = 0;

  /// Handshake counters (see [status]): one hello per connection attempt,
  /// one welcome per accepted handshake.
  int _hellos = 0;
  int _welcomes = 0;

  Completer<String> _firstWelcome = Completer<String>();
  Completer<bool>? _welcomeCompleter;

  /// Request doors as waiter LISTS: an answer (or failure) fans out to
  /// EVERY current waiter, so a concurrent caller (the 15s PendingInvites
  /// poller vs a tool's resolve, an inbound-DM whois vs a sendDm) can
  /// never clobber an earlier one — 0.1.3's single slots orphaned it.
  final _flushWaiters = <Completer<int>>[];

  /// Pending `presence_query` callers, each with the frame id its answer
  /// must echo in `replyTo` (see [_onPresence] for the matching rule).
  final _presenceWaiters = <_PresenceWaiter>[];

  /// Whether this hub has EVER echoed `replyTo` on a presence frame —
  /// sticky for the client's lifetime (survives reconnects, which is
  /// where the startup race recurs). Once set, a replyTo-less presence
  /// frame is a known broadcast and never completes waiters; a hub that
  /// never echoes stays on the legacy one-completes-all path.
  bool _replyToEchoSeen = false;

  final _pendingWhois = <String, List<Completer<AgentInfo>>>{};
  final _whoisCache = <String, AgentInfo>{};

  final _inbound = StreamController<InboundMessage>.broadcast();
  final _errors = StreamController<HubError>.broadcast();

  final _joinDenials = StreamController<JoinDenied>.broadcast();

  /// Channels the hub denied (issue #1016): `_joinKnownChannels` skips
  /// these on later reconnects instead of re-attempting forever.
  final Set<String> _joinDenied = {};

  /// Joins sent on the CURRENT connection, in send order — the hub
  /// answers denials in the same order (one TCP stream, in-order
  /// processing) and the error frame never names the channel, so a
  /// denial pops the FIFO head.
  final List<String> _joinPending = [];
  final _welcomeEvents = StreamController<void>.broadcast();

  /// All inbound `msg` frames, oldest first.
  Stream<InboundMessage> get inbound => _inbound.stream;

  /// Every hub `error` frame received (unknown_agent, access_denied, …).
  /// Hub rejections must never be silent — listeners surface them.
  Stream<HubError> get errors => _errors.stream;

  /// Every channel join the hub denied (issue #1016): channel, code and
  /// msg — hosts render "not invited / wrong channel id" instead of a
  /// silent absence. An explicit [join] retries (and clears) the mark.
  Stream<JoinDenied> get joinDenials => _joinDenials.stream;

  /// Fires after every accepted welcome (first connect and each
  /// reconnect) — the restart-redelivery hook for pending invites.
  Stream<void> get welcomeEvents => _welcomeEvents.stream;

  /// True while a welcome was received on a currently open socket and the
  /// client was not deliberately disconnected ([disconnect]). The
  /// `!_closing` guard matters: dart:io can leave `readyState` at `open`
  /// even after `close()` completed, so without it a post-disconnect
  /// [status] would claim `connected: true`.
  bool get connected =>
      !_closing &&
      _ws != null &&
      _ws!.readyState == WebSocket.open &&
      _firstWelcome.isCompleted;

  /// Completes with our agent id after the first welcome.
  Future<String> get welcomed => _firstWelcome.future;

  /// Our hub agent id once the hub welcomed us.
  String? agentId;

  /// Request cap for whois/flush/presenceQuery (see [requestTimeout]).
  static const defaultRequestTimeout = Duration(seconds: 10);

  /// 1 s doubling, capped at 30 s (spec "Client reconnect").
  static Duration defaultBackoff(int attempt) {
    // Clamp BEFORE shifting: `1 << (attempt - 1)` overflows 64-bit shift
    // semantics — attempt 64 is negative and attempt 65+ is ZERO, so the
    // `seconds > 30` cap never fired and the delay degenerated to
    // Duration.zero: a tight reconnect loop burning a full core forever
    // (observed live at _reconnectAttempt = 69,730,601).
    if (attempt >= 6) return const Duration(seconds: 30);
    return Duration(seconds: 1 << (attempt - 1));
  }

  /// Connects and keeps the connection alive until [disconnect]. Completes
  /// after the first welcome; a later drop re-hellos (after backoff) and
  /// flushes the offline mailbox again. A rejected hello completes this
  /// future with [HubError].
  bool _loopStarted = false;

  Future<String> connect() {
    if (config.url == null) {
      return Future.error(StateError('hub config has no url'));
    }
    if (!_loopStarted) {
      _loopStarted = true;
      _closing = false;
      unawaited(_connectLoop(++_epoch));
    }
    return _firstWelcome.future;
  }

  Future<void> _connectLoop(int epoch) async {
    while (!_closing && epoch == _epoch) {
      var welcomed = false;
      try {
        welcomed = await _cycle(epoch);
      } on HubError catch (error) {
        // pre-welcome rejection (bad signature, …) — fatal, stop retrying
        if (!_firstWelcome.isCompleted) _firstWelcome.completeError(error);
        return;
      } on Object {
        // unexpected cycle failure — treat as unwelcomed cycle
      }
      if (_closing || epoch != _epoch) return;
      if (welcomed) _reconnectAttempt = 0;
      _reconnectAttempt++;
      await Future<void>.delayed(backoff(_reconnectAttempt));
    }
  }

  /// One connect → hello → welcome → flush → hold-until-close cycle.
  /// Returns whether the hub welcomed us; only pre-welcome hub rejections
  /// throw ([HubError]) — transport failures just return `false`.
  Future<bool> _cycle(int epoch) async {
    final WebSocket ws;
    try {
      ws = await WebSocket.connect(config.url!, headers: {
        if (_clientSecret != null)
          HttpHeaders.authorizationHeader: 'Bearer $_clientSecret',
      });
    } on WebSocketException catch (error) {
      if (error.httpStatusCode == HttpStatus.unauthorized) {
        // One-shot recovery for a stale persisted cache; ineligible or
        // re-rejected -> `null` and the frozen hint below stays fatal.
        final retried = await _recoverStaleSecret(epoch);
        if (retried != null) return retried;
        // Bearer rejected before any websocket — fatal, no retry: the
        // frozen text tells the operator how to enroll or connect.
        final rejection = HubError('unauthorized', unauthorizedMsg);
        if (!_errors.isClosed) _errors.add(rejection); // never silent
        throw rejection;
      }
      _failPending('connect failed');
      return false;
    } on Object {
      _failPending('connect failed');
      return false;
    }
    // Stale-socket guard: a retarget while we were parked inside
    // WebSocket.connect retired this generation — the socket is dead on
    // arrival. Close it and touch nothing shared (no _ws/_subscription
    // clobber, no hello, no reconnect war).
    if (_closing || epoch != _epoch) {
      await ws.close();
      return false;
    }
    _ws = ws;
    ws.pingInterval = pingInterval; // native liveness watchdog (see field doc)
    final welcomed = Completer<bool>();
    // A drop BEFORE anyone awaits (the socket dies while the hello is
    // still signing — 'Bad state: connection closed before welcome' in
    // the wild, issue #988) must not turn the completer's error into an
    // unhandled zone error that kills the host. ignore() only silences
    // the nobody-awaited-it case; the await below still sees the error.
    welcomed.future.ignore();
    final done = Completer<void>();
    _welcomeCompleter = welcomed;
    late final StreamSubscription sub;
    sub = ws.listen(
      (dynamic data) {
        // Superseded sockets must not touch the live generation's state.
        if (epoch == _epoch) _onFrame(data as String);
      },
      onDone: () => _abandon(welcomed, done),
      onError: (Object _) => _abandon(welcomed, done),
      cancelOnError: true,
    );
    _hellos++;
    ws.add(jsonEncode(await _helloFrame()));
    if (_enroll) ws.add(jsonEncode(const {'t': 'enroll'}));
    final bool ok;
    try {
      ok = await welcomed.future;
    } on StateError {
      // transport died before welcome — plain retry
      await done.future;
      return false;
    } on HubError {
      // hub rejected the hello — close our side, propagate
      await sub.cancel();
      await ws.close();
      rethrow;
    }
    if (ok && epoch == _epoch) {
      agentId = _welcomedAgentId;
      if (!_firstWelcome.isCompleted) _firstWelcome.complete(agentId);
      await _joinKnownChannels();
      await _flushAfterWelcome();
      await _warmUpPresence();
      if (!_welcomeEvents.isClosed) _welcomeEvents.add(null);
    }
    await done.future;
    return ok;
  }

  String? _welcomedAgentId;

  /// One-shot stale-config-secret recovery, the 401 escalation path: a
  /// rejected secret that came from `~/.dap/config.json` (never from
  /// the env — that is explicit user intent) is dropped from the
  /// persisted config and the dial runs once more in enroll-mode with
  /// the master secret. The re-enroll binds to the same hello name, so
  /// key files and agent identity stay untouched; the newly issued
  /// secret is persisted through the same path as a first enroll.
  ///
  /// Returns the retry cycle's outcome (welcomed or not), or `null`
  /// when ineligible (already escalated, env-sourced or master-less)
  /// or when the retry 401'd again — the caller then throws the frozen
  /// hint. Any other pre-welcome rejection propagates untouched.
  Future<bool?> _recoverStaleSecret(int epoch) async {
    if (_reenrolled ||
        _secretSource != DapSecretSource.config ||
        _masterSecret == null) {
      return null;
    }
    _reenrolled = true; // exactly one retry, never a loop
    await _dropStaleConfigSecret();
    _clientSecret = _masterSecret;
    _enroll = true;
    _secretSource = DapSecretSource.master;
    try {
      return await _cycle(epoch);
    } on HubError catch (retry) {
      if (retry.code != 'unauthorized') rethrow;
      return null;
    }
  }

  void _abandon(Completer<bool> welcomed, Completer<void> done) {
    if (!welcomed.isCompleted) {
      welcomed.completeError(StateError('connection closed before welcome'));
    }
    _failPending('connection closed');
    if (!done.isCompleted) done.complete();
  }

  Future<void> disconnect() async {
    _closing = true;
    await _subscription?.cancel();
    await _ws?.close();
    _failPending('disconnecting');
    if (!_firstWelcome.isCompleted) {
      _firstWelcome.completeError(StateError('disconnected'));
    }
    await _inbound.close();
    await _errors.close();
    await _joinDenials.close();
    await _welcomeEvents.close();
  }

  Future<String> retarget(
      {String? url, HubIdentity? keys, String? name}) async {
    _epoch++; // retire any loop parked in backoff (no double-connect)
    _closing = true;
    // Paired teardown with no await gap between reading and clearing the
    // fields: a cycle completing mid-retarget could reassign _ws in that
    // gap, splitting cancel(socket A)/close(socket B) and stranding a
    // hub-registered, subscription-less zombie socket.
    final ws = _ws;
    final sub = _subscription;
    _ws = null;
    _subscription = null;
    _failPending('retargeting');
    await sub?.cancel();
    await ws?.close();
    if (keys != null) {
      _identity = keys;
      _whoisCache.clear(); // peer keys resolved under the old identity
      _welcomedAgentId = null;
      agentId = keys.agentId;
    }
    if (url != null || name != null) {
      _config = HubConfig(
        url: url ?? _config.url,
        keyPath: _config.keyPath,
        name: name ?? _config.name,
        channels: _config.channels,
        channelSecrets: _config.channelSecrets,
      );
    }
    if (!_firstWelcome.isCompleted) {
      _firstWelcome.completeError(StateError('retargeted'));
    }
    _firstWelcome = Completer<String>();
    _loopStarted = false;
    _closing = false;
    return connect();
  }

  /// dap_connect on the live client (see [HubPlugin.connectTo] for the
  /// full flow with config persistence): normalize [host] (no scheme →
  /// `ws://`, no path → `/ws`), optional [name] = display name AND
  /// identity (name-derived key file `~/.dap/keys/fah/<name>.key`,
  /// auto-created 0600 — a new name is a new agentId), optional
  /// [channel] = default room (keypair ensured in the store when
  /// unknown; joined after the new welcome and on every later launch
  /// via the shared channels file). Completes at the new hub's welcome
  /// and returns the connection now in force.
  ///
  /// NOTE: if the room already exists on the target hub under another
  /// member's key, ask a member for a dap_invite — a blind join lets
  /// you post, but the members cannot read you.
  Future<DapConnection> connectTo(String host,
      {String? name, String? channel, String? home}) async {
    final url = normalizeDapHost(host);
    HubIdentity? keys;
    if (name != null) {
      keys = await HubIdentity.load(
          defaultDapKeyPath(name, home ?? defaultHome(Platform.environment)));
    }
    if (channel != null) {
      final store = channelStore;
      if (store == null) {
        throw StateError('default room "$channel" needs a channel store');
      }
      await store.keysFor(channel); // keygen + persist when unknown
    }
    final id = await retarget(url: url, keys: keys, name: name);
    return (
      ok: true,
      url: url,
      name: config.name,
      agentId: id,
      channels: knownChannels,
    );
  }

  // ---- outbound ----

  Future<Map<String, dynamic>> _helloFrame() async {
    final frame = <String, dynamic>{
      'op': 'hello',
      'v': 1,
      'pubkey': identity.signingPubkeyB64,
      'x25519': identity.dhPubkeyB64,
      'nonce': randomHex(16),
      'ts': DateTime.now().millisecondsSinceEpoch,
      if (config.name != null) 'name': config.name,
    };
    frame['sig'] = await signFrame(frame, identity.signingKeyPair);
    return frame;
  }

  /// Channel membership (spec § join): the first join creates the channel
  /// and registers [chanPubkeyB64]; re-join is idempotent — safe after
  /// every reconnect.
  void join(String channel, String chanPubkeyB64) {
    // An explicit join retries even a previously denied channel — an
    // invite may have arrived since (issue #1016).
    _joinDenied.remove(channel);
    _joinPending.add(channel);
    _send({'op': 'join', 'channel': channel, 'chanPubkey': chanPubkeyB64});
  }

  /// Membership: join every known channel after each welcome (idempotent,
  /// reconnect-safe). A failed join is transient — the reconnect loop
  /// retries after the next welcome.
  Future<void> _joinKnownChannels() async {
    // Pending order is per connection: the FIFO is rebuilt from what we
    // actually send below, so stale entries can never mis-match a denial
    // from a previous socket (issue #1016).
    _joinPending.clear();
    try {
      final store = channelStore;
      if (store != null) {
        for (final entry in store.all.entries) {
          if (_joinDenied.contains(entry.key)) continue;
          join(entry.key, entry.value.pub);
        }
      }
      for (final entry in config.channels.entries) {
        if (_joinDenied.contains(entry.key)) continue;
        if (store == null || !store.knows(entry.key))
          join(entry.key, entry.value);
      }
    } on Object {
      // socket dropped mid-join — the reconnect loop re-runs us
    }
  }

  /// E2E-encrypted send to every member of [channel] under the channel
  /// pubkey; the first send to an unknown channel auto-keygens + joins.
  Future<void> sendToChannel(String channel, String text) async {
    final pubkeyB64 = await _channelPubFor(channel);
    await _sendEncrypted(
      extra: {'channel': channel},
      recipientDhPubkey: _dhPubkey(pubkeyB64),
      aadTarget: channel,
      text: text,
    );
  }

  /// Advanced: sends a channel payload sealed by the CALLER. [seal] runs
  /// with the freshly minted frame id (the AEAD AAD binds to it:
  /// `dap1|<frameId>|<channel>`) and returns the base64 ciphertext.
  ///
  /// Use this to emit a self-describing envelope — e.g. the fa_network
  /// `fanet1` frame `base64(0x01 || senderX25519(32) || nonce(12) || ct ||
  /// tag)` — so recipients without hub whois access (the fa_network relay
  /// passes payloads through byte-identical and stamps its own sender id)
  /// can still decrypt.
  Future<void> sendChannelEnvelope(
    String channel,
    Future<String> Function(String frameId) seal,
  ) async {
    final id = newFrameId();
    final ciphertext = await seal(id);
    final frame = <String, dynamic>{
      'op': 'send',
      'channel': channel,
      'id': id,
      'ts': DateTime.now().millisecondsSinceEpoch,
      'ciphertext': ciphertext,
    };
    frame['sig'] = await signFrame(frame, identity.signingKeyPair);
    _send(frame);
  }

  /// Explicit config first; otherwise the store auto-generates + persists
  /// the keypair and joins — creating the channel (spec § join: senders
  /// only need the channel public key).
  Future<String> _channelPubFor(String channel) async {
    final explicit = config.channels[channel];
    if (explicit != null) return explicit;
    final store = channelStore;
    if (store == null) {
      throw ArgumentError('no channel pubkey configured for "$channel"');
    }
    final keys = await _channelKeysOrCreate(channel, store);
    return keys.pub;
  }

  /// Keys for [channel] via [store], joining too when the keypair was just
  /// created (zero-config channel creation).
  Future<ChannelKeys> _channelKeysOrCreate(
      String channel, ChannelStore store) async {
    final existed = store.knows(channel);
    final keys = await store.keysFor(channel);
    if (!existed) join(channel, keys.pub);
    return keys;
  }

  /// Invites [toAgentId] to [channel]: DMs them the channel keypair as a
  /// normal E2E DM whose plaintext is the chankey JSON (spec § "Channel key
  /// distribution"). Trust model: possession of the channel private key IS
  /// v1 membership; the introducer is whoever DM'd you the key.
  Future<void> inviteTo(String channel, String toAgentId) async {
    final keys = await ensureChannelKeys(channel);
    await sendDm(
      toAgentId,
      jsonEncode({
        't': 'chankey',
        'channel': channel,
        'pub': keys.pub,
        'priv': keys.priv
      }),
    );
  }

  /// Channel keys for invites and sends: the store auto-generates +
  /// persists the keypair and joins when it was just created (zero-config
  /// channel creation — also the arm-time path for pending invites);
  /// explicit-config-only clients fall back to the configured secret
  /// (honest error when absent).
  Future<ChannelKeys> ensureChannelKeys(String channel) async {
    final store = channelStore;
    return store != null
        ? await _channelKeysOrCreate(channel, store)
        : await _keysFromConfig(channel);
  }

  /// Explicit-config fallback: priv is required (it is the invite payload),
  /// pub is derived from it when only the secret is configured.
  Future<ChannelKeys> _keysFromConfig(String channel) async {
    final priv = config.channelSecrets[channel];
    if (priv == null) {
      throw StateError(
          'no channel key for "$channel" — an invite needs the private key');
    }
    var pub = config.channels[channel];
    final fromSeed = await X25519().newKeyPairFromSeed(base64Decode(priv));
    pub ??= base64Encode((await fromSeed.extractPublicKey()).bytes);
    return ChannelKeys(pub: pub, priv: priv);
  }

  /// Sends an E2E DM. Whois resolves the peer's X25519 pubkey on first use.
  Future<void> sendDm(String toAgentId, String text) async {
    final peer = await whois(toAgentId);
    final peerKey = peer.dhPublicKey;
    if (peerKey == null) {
      throw StateError('hub returned no x25519 pubkey for "$toAgentId"');
    }
    await _sendEncrypted(
      extra: {'to': toAgentId},
      recipientDhPubkey: peerKey,
      aadTarget: toAgentId,
      text: text,
    );
  }

  Future<void> _sendEncrypted({
    required Map<String, dynamic> extra,
    required SimplePublicKey recipientDhPubkey,
    required String aadTarget,
    required String text,
  }) async {
    final id = newFrameId();
    final ciphertext = await encryptPayload(
      senderDhKeyPair: identity.dhKeyPair,
      recipientDhPubkey: recipientDhPubkey,
      frameId: id,
      aadTarget: aadTarget,
      plaintext: text,
    );
    final frame = <String, dynamic>{
      'op': 'send',
      ...extra,
      'id': id,
      'ts': DateTime.now().millisecondsSinceEpoch,
      'ciphertext': ciphertext,
    };
    frame['sig'] = await signFrame(frame, identity.signingKeyPair);
    _send(frame);
  }

  /// Awaits a request door with [requestTimeout]; on timeout, runs
  /// [cleanup] (release the pending slot so a late answer cannot
  /// complete a dead request) and fails loudly instead of hanging.
  Future<T> _withTimeout<T>(
    Future<T> future,
    String op,
    void Function() cleanup,
  ) {
    return future.timeout(requestTimeout, onTimeout: () {
      cleanup();
      final waited = requestTimeout.inSeconds > 0
          ? '${requestTimeout.inSeconds}s'
          : '${requestTimeout.inMilliseconds}ms';
      throw StateError('hub did not answer $op within $waited');
    });
  }

  /// Whois with caching — the spec-required lookup before a first DM.
  /// [targetAgentId] is the 16-hex DAP id — discover ids via [peers]
  /// (presence), not names.
  Future<AgentInfo> whois(String targetAgentId) async {
    final cached = _whoisCache[targetAgentId];
    if (cached != null) return cached;
    final completer = Completer<AgentInfo>();
    _pendingWhois.putIfAbsent(targetAgentId, () => []).add(completer);
    try {
      _send({'op': 'whois', 'agentId': targetAgentId});
    } on Object {
      // never answered — don't leak it
      _dropWhoisWaiter(targetAgentId, completer);
      rethrow;
    }
    final info = await _withTimeout(
      completer.future,
      'whois',
      () => _dropWhoisWaiter(targetAgentId, completer),
    );
    _whoisCache[targetAgentId] = info;
    return info;
  }

  /// Releases exactly this caller's waiter (send failure / request
  /// timeout); concurrent waiters on the same target stay registered.
  void _dropWhoisWaiter(String targetAgentId, Completer<AgentInfo> completer) {
    final waiters = _pendingWhois[targetAgentId];
    if (waiters == null) return;
    waiters.remove(completer);
    if (waiters.isEmpty) _pendingWhois.remove(targetAgentId);
  }

  /// Drains the hub-side offline mailbox; returns the drained count.
  Future<int> flush() {
    final completer = Completer<int>();
    _flushWaiters.add(completer);
    _send({'op': 'flush'});
    return _withTimeout(
      completer.future,
      'flush',
      () => _flushWaiters.remove(completer),
    );
  }

  /// Sends `presence_query` with a fresh frame id; the hub's ANSWER
  /// echoes that id in `replyTo` and completes this caller only
  /// (docs/protocol.md §presence — see [_onPresence] for the full
  /// matching rule, legacy hubs included). [requestTimeout] caps the
  /// door either way.
  Future<List<AgentInfo>> presenceQuery() {
    final waiter = (
      requestId: newFrameId(),
      completer: Completer<List<AgentInfo>>(),
    );
    _presenceWaiters.add(waiter);
    try {
      _send({'op': 'presence_query', 'id': waiter.requestId});
    } on Object {
      // never answered — don't leak a listener-less waiter (whois pattern)
      _presenceWaiters.remove(waiter);
      rethrow;
    }
    return _withTimeout(
      waiter.completer.future,
      'presence_query',
      () => _presenceWaiters.remove(waiter),
    );
  }

  /// Presence list from the hub (`dap_peers`): ONLINE ONLY — one
  /// [AgentInfo] per connected agent, our own entry included and marked
  /// [AgentInfo.self]. Same wire op as [presenceQuery].
  Future<List<AgentInfo>> peers() async {
    final me = agentId;
    return [
      for (final agent in await presenceQuery())
        if (agent.online) agent.agentId == me ? agent.asSelf() : agent,
    ];
  }

  /// Welcome-time warm-up (every fresh connection): a throwaway
  /// `presence_query` whose only job is to make the hub echo `replyTo`,
  /// arming [_replyToEchoSeen] BEFORE any consumer query — without it
  /// the startup join self-echo (a replyTo-less broadcast) can drain
  /// the first query's waiter with a one-agent roster. Up to 2 retries
  /// while still unarmed; a legacy hub answers without `replyTo`, so
  /// the latch stays unarmed and the one-completes-all path stays. The
  /// result is discarded; errors are swallowed — a reconnect re-runs
  /// this after the next welcome.
  Future<void> _warmUpPresence() async {
    for (var left = 3; left > 0 && !_replyToEchoSeen; left--) {
      try {
        await presenceQuery();
      } on Object {
        return; // silent/erroring hub or mid-warm-up drop
      }
    }
  }

  /// Snapshot for the `dap_status` tool — safe to call any time, also
  /// before the first welcome or after a drop (then `connected` is false
  /// and the counters tell the reconnect story).
  HubStatus status() => HubStatus(
        connected: connected,
        agentId: agentId,
        name: config.name,
        url: config.url,
        channels: knownChannels,
        welcomes: _welcomes,
        hellos: _hellos,
      );

  /// Every channel this client can send to: store keys (zero-config
  /// lifecycle) ∪ explicit config keys, sorted.
  List<String> get knownChannels => {
        ...?channelStore?.all.keys,
        ...config.channels.keys,
      }.toList()
        ..sort();

  void _send(Map<String, dynamic> frame) {
    final ws = _ws;
    if (ws == null || ws.readyState != WebSocket.open) {
      throw StateError(
          'not connected to the hub (reconnecting with backoff — retry in a moment)');
    }
    ws.add(jsonEncode(frame));
  }

  // ---- inbound ----

  /// Frame-pump guard: whatever a single inbound frame's handler throws,
  /// it must die HERE (as an onNotice) — never escape into the zone and
  /// kill the host process. A hostile or buggy hub/peer sends one bad
  /// frame; the connection and every later frame must survive it.
  Future<void> _onFrame(Object data) async {
    final Map<String, dynamic> frame;
    try {
      frame = (jsonDecode(data as String) as Map).cast<String, dynamic>();
    } on FormatException {
      return;
    }
    try {
      await _dispatchFrame(frame);
    } on Object catch (e) {
      onNotice?.call('malformed hub frame ignored: $e');
    }
  }

  Future<void> _dispatchFrame(Map<String, dynamic> frame) async {
    if (frame['t'] == 'enrolled') {
      _onEnrolled(frame['secret'] as String?);
      return;
    }
    switch (frame['op'] as String?) {
      case 'welcome':
        _welcomes++;
        _welcomedAgentId = frame['agentId'] as String?;
        _completeWelcome(true);
      case 'error':
        _onError(frame);
      case 'joined':
        // Success ack names the channel — drop it from the pending FIFO
        // so a later access_denied can only attribute to joins the hub
        // has not acked yet (the denial frame never names its channel).
        _joinPending.remove(frame['channel'] as String?);
      case 'msg':
        await _onMsg(frame);
      case 'agent_info':
        _onAgentInfo(frame);
      case 'presence':
        _onPresence(frame);
      case 'flushed':
        final count = frame['count'] as int? ?? 0;
        for (final waiter in _drain(_flushWaiters)) {
          if (!waiter.isCompleted) waiter.complete(count);
        }
    }
  }

  /// Removes the persisted clientSecret after the hub rejected it — a
  /// provably dead cache that would otherwise win precedence over the
  /// master secret on every later launch and 401 forever.
  Future<void> _dropStaleConfigSecret() async {
    final file = configFile;
    if (file == null) return;
    await persistDapConfig(clearClientSecret: true, file: file);
  }

  /// Hub accepted the enrollment: the issued secret replaces the master
  /// secret for every future dial (reconnects included), enrollment
  /// stops, and the secret is persisted to [configFile] — never logged.
  void _onEnrolled(String? secret) {
    if (!_enroll || secret == null || secret.isEmpty) return;
    _enroll = false;
    _clientSecret = secret;
    unawaited(_persistEnrolled());
  }

  Future<void> _persistEnrolled() async {
    try {
      final file = configFile;
      if (file != null) {
        await persistDapConfig(clientSecret: _clientSecret, file: file);
      }
      onNotice?.call('enrolled: client secret persisted');
    } on Object catch (error) {
      onNotice?.call('enroll persistence failed: $error');
    }
  }

  void _onError(Map<String, dynamic> frame) {
    final error = HubError(
      frame['code'] as String? ?? 'unknown',
      frame['msg'] as String? ?? '',
    );
    if (!_errors.isClosed) _errors.add(error); // never silent
    // Master-gated hubs answer a denied join with access_denied (issue
    // #1016). The frame carries no channel id; the hub processes joins
    // in arrival order over one ordered stream, so the denial maps to
    // the FIFO head of this connection's pending joins.
    if (error.code == 'access_denied' && _joinPending.isNotEmpty) {
      final channel = _joinPending.removeAt(0);
      _joinDenied.add(channel);
      if (!_joinDenials.isClosed) {
        _joinDenials.add(JoinDenied(channel, error.code, error.msg));
      }
    }
    final welcome = _welcomeCompleter;
    if (welcome != null && !welcome.isCompleted) {
      _welcomeCompleter = null;
      welcome.completeError(error);
      return;
    }
    for (final waiters in _pendingWhois.values) {
      _failAll(waiters, error);
    }
    _pendingWhois.clear();
    _failFlushPresence(error);
  }

  Future<void> _onMsg(Map<String, dynamic> frame) async {
    final channel = frame['channel'] as String?;
    String? plaintext;
    try {
      plaintext = channel != null
          ? await _decryptChannel(channel, frame)
          : await _decryptDm(frame);
    } on Object {
      plaintext = null; // no key or tampered payload — deliver opaque
    }
    if (_inbound.isClosed) return;
    // A chankey DM is an invite, not chat: persist the keypair, join, and
    // surface a short notice — never the raw key JSON.
    if (channel == null && plaintext != null) {
      final store = channelStore;
      final invite = parseChankeyInvite(plaintext);
      if (invite != null && store != null) {
        await store.accept(
          invite.channel,
          ChannelKeys(pub: invite.pub, priv: invite.priv),
        );
        join(invite.channel, invite.pub);
        plaintext = '[hub] invited to #${invite.channel} by ${frame['from']}';
      }
    }
    _inbound.add(InboundMessage(
      id: frame['id'] as String? ?? '',
      from: frame['from'] as String? ?? '',
      ts: frame['ts'] as int? ?? 0,
      channel: channel,
      to: frame['to'] as String?,
      plaintext: plaintext,
    ));
  }

  Future<String> _decryptChannel(String channel, Map frame) async {
    final privB64 =
        channelStore?.privOf(channel) ?? config.channelSecrets[channel];
    final pubB64 = channelStore?.pubOf(channel) ?? config.channels[channel];
    if (privB64 == null || pubB64 == null) throw StateError('no channel key');
    // Sender encrypted with senderPriv x channelPub; we decrypt with
    // channelPriv x senderPub (the sender is a registered agent).
    final sender = await whois(frame['from'] as String);
    final senderKey = sender.dhPublicKey;
    if (senderKey == null) throw StateError('no sender dh pubkey');
    return decryptPayload(
      recipientDhKeyPair: SimpleKeyPairData(
        base64Decode(privB64),
        publicKey: _dhPubkey(pubB64),
        type: KeyPairType.x25519,
      ),
      senderDhPubkey: senderKey,
      frameId: frame['id'] as String,
      aadTarget: channel,
      ciphertextB64: frame['ciphertext'] as String,
    );
  }

  Future<String> _decryptDm(Map frame) async {
    final me = agentId;
    if (me == null) throw StateError('not welcomed');
    final sender = await whois(frame['from'] as String);
    final senderKey = sender.dhPublicKey;
    if (senderKey == null) throw StateError('no sender dh pubkey');
    return decryptPayload(
      recipientDhKeyPair: identity.dhKeyPair,
      senderDhPubkey: senderKey,
      frameId: frame['id'] as String,
      aadTarget: me,
      ciphertextB64: frame['ciphertext'] as String,
    );
  }

  void _onAgentInfo(Map<String, dynamic> frame) {
    final info = _infoFrom(frame);
    final waiters = _pendingWhois.remove(info.agentId);
    if (waiters == null) return;
    for (final waiter in waiters) {
      if (!waiter.isCompleted) waiter.complete(info);
    }
  }

  /// Presence frame routing — the waiter matching rule (docs/protocol.md
  /// §presence):
  ///
  /// * `replyTo` present: an ANSWER to our `presence_query` — the hub
  ///   echoes the request frame id. Completes EXACTLY the waiters whose
  ///   request id matches (fan-out included); concurrent queries carry
  ///   their own ids and stay pending for their own echo. A late echo
  ///   for an already-timed-out query matches nobody: dropped.
  /// * `replyTo` absent on a hub KNOWN to echo (any echo seen before):
  ///   an unsolicited broadcast push (join/leave). Never completes
  ///   waiters — that is the BUG 5 race (a one-agent broadcast drained
  ///   pending waiters, so `peers()` returned a one-agent roster). No
  ///   presence roster cache is kept, so the frame is dropped.
  /// * `replyTo` absent on a hub never seen to echo (legacy): answers
  ///   and broadcasts share one indistinguishable frame shape, so the
  ///   0.1.4 one-completes-all semantics stay — the frame completes
  ///   every current waiter (old hubs keep working). The welcome-time
  ///   warm-up ([_warmUpPresence]) fires a throwaway echoed query on
  ///   every fresh connection, arming the latch before any consumer
  ///   query — the first-query steal window is closed.
  void _onPresence(Map<String, dynamic> frame) {
    final agents = <AgentInfo>[];
    for (final raw in (frame['agents'] as List? ?? const [])) {
      // Roster entries are peer-controlled: a non-map row or an entry
      // without a String agentId is skipped with a notice, never a cast
      // crash (issue #988).
      if (raw is! Map) {
        onNotice?.call('presence: skipping non-map roster entry '
            '(${raw.runtimeType})');
        continue;
      }
      final entry = raw.cast<String, dynamic>();
      if (entry['agentId'] is! String) {
        onNotice?.call('presence: skipping roster entry without agentId');
        continue;
      }
      agents.add(_infoFrom(entry));
    }
    final replyTo = frame['replyTo'];
    if (replyTo is String && replyTo.isNotEmpty) {
      _replyToEchoSeen = true;
      for (final waiter in _drainPresence((w) => w.requestId == replyTo)) {
        if (!waiter.completer.isCompleted) waiter.completer.complete(agents);
      }
      return;
    }
    if (_replyToEchoSeen) return; // known-echoing hub: broadcast push
    for (final waiter in _drainPresence((_) => true)) {
      if (!waiter.completer.isCompleted) waiter.completer.complete(agents);
    }
  }

  AgentInfo _infoFrom(Map<String, dynamic> frame) {
    final dhB64 = frame['x25519'] as String?;
    final agentId = frame['agentId'] as String;
    SimplePublicKey? dh;
    if (dhB64 != null && dhB64.isNotEmpty) {
      dh = _tryDhPubkey(dhB64);
      if (dh == null) {
        // Peer-controlled string we could not use — E2E with that peer
        // is disabled, the roster entry stays (issue #988).
        onNotice?.call('peer $agentId advertises an unusable x25519 key '
            '(E2E with it disabled)');
      }
    }
    final lastSeenMs = frame['lastSeen'] as int?;
    return AgentInfo(
      agentId: agentId,
      name: frame['name'] as String?,
      online: frame['online'] as bool? ?? false,
      signingPubkeyB64: frame['pubkey'] as String?,
      dhPublicKey: dh,
      lastSeen: lastSeenMs == null
          ? null
          : DateTime.fromMillisecondsSinceEpoch(lastSeenMs, isUtc: true),
    );
  }

  Future<void> _flushAfterWelcome() async {
    try {
      await flush();
    } on Object {
      // hub without flush support or early drop — non-fatal
    }
  }

  void _completeWelcome(bool ok) {
    final welcome = _welcomeCompleter;
    _welcomeCompleter = null;
    if (welcome != null && !welcome.isCompleted) welcome.complete(ok);
  }

  /// Detaches the current waiters before completing them: a caller that
  /// registers mid-iteration is never hit by an answer already delivered.
  List<Completer<T>> _drain<T>(List<Completer<T>> waiters) {
    final pending = List.of(waiters);
    waiters.clear();
    return pending;
  }

  /// [_drain]'s guard for presence waiters: detaches the matching entries
  /// before completing them, so a caller registering mid-iteration is
  /// never hit by an answer already delivered.
  List<_PresenceWaiter> _drainPresence(
    bool Function(_PresenceWaiter waiter) test,
  ) {
    final matched = _presenceWaiters.where(test).toList();
    _presenceWaiters.removeWhere(test);
    return matched;
  }

  /// Fails the pending flush/presence doors with [error] and frees their
  /// slots — shared by [_onError] (hub answered with an error frame) and
  /// [_failPending] (connection-level teardown).
  void _failFlushPresence(Object error) {
    _failAll(_flushWaiters, error);
    for (final waiter in _drainPresence((_) => true)) {
      if (!waiter.completer.isCompleted) waiter.completer.completeError(error);
    }
  }

  /// Fan-out failure: every waiter of a door gets [error], list emptied.
  void _failAll<T>(List<Completer<T>> waiters, Object error) {
    for (final waiter in _drain(waiters)) {
      if (!waiter.isCompleted) waiter.completeError(error);
    }
  }

  void _failPending(String reason) {
    final welcome = _welcomeCompleter;
    _welcomeCompleter = null;
    if (welcome != null && !welcome.isCompleted) {
      welcome.completeError(StateError(reason));
    }
    for (final waiters in _pendingWhois.values) {
      _failAll(waiters, StateError(reason));
    }
    _pendingWhois.clear();
    _failFlushPresence(StateError(reason));
  }

  static SimplePublicKey _dhPubkey(String b64) =>
      SimplePublicKey(base64Decode(b64), type: KeyPairType.x25519);

  /// Tolerant decode of a PEER-CONTROLLED x25519 string (presence /
  /// agent_info): trims, strips quotes, percent-decodes `%3D` padding,
  /// maps the base64url `-_` alphabet onto standard and re-pads. Returns
  /// null when the result is not exactly 32 decodable bytes — never
  /// throws (issue #988: a JS client's unpadded 43-char key must not
  /// kill the process).
  static SimplePublicKey? _tryDhPubkey(String raw) {
    var s = raw.trim();
    if (s.length >= 2 && s.startsWith('"') && s.endsWith('"')) {
      s = s.substring(1, s.length - 1).trim();
    }
    if (s.contains('%')) {
      try {
        s = Uri.decodeComponent(s);
      } on FormatException {
        return null;
      }
    }
    s = s.replaceAll('-', '+').replaceAll('_', '/');
    final rem = s.length % 4;
    if (rem == 1) return null; // no base64 shape has this length
    if (rem == 2 || rem == 3) s += '=' * (4 - rem);
    try {
      final bytes = base64Decode(s);
      if (bytes.length != 32) return null; // x25519 keys are 32 bytes
      return SimplePublicKey(bytes, type: KeyPairType.x25519);
    } on FormatException {
      return null;
    }
  }
}

/// Pending by-name invites — `dap_invite <name>` against a user not yet
/// on the hub: persisted in the machine-shared `~/.dap/config.json` under
/// `invites: [{name, channel}]`, delivered automatically once the name
/// appears online. One presence query per [interval] (~15 s) plus an
/// immediate check at arm time and after every welcome (restart
/// redelivery). Mirrors the omp-extension pending-invite behavior.
class PendingInvites {
  PendingInvites({
    required this.client,
    required this.configFile,
    this.onNotice,
    this.interval = const Duration(seconds: 15),
  });

  /// The inviter's connection: presence, chankey DMs, channel creation.
  final HubClient client;

  /// `~/.dap/config.json` — the authoritative pending list (injectable
  /// test seam).
  final String configFile;

  /// Short user-facing notices ('invited X to #c', check failures) — the
  /// host wires this to its terminal; failures are never silent.
  final void Function(String notice)? onNotice;

  /// Poll interval (injectable test seam — shrink for fast ticks).
  final Duration interval;

  static const String notConnected =
      'not connected to the hub (reconnecting with backoff — retry in a moment)';

  static final RegExp _idPattern = RegExp(r'^[0-9a-f]{16}$');

  final _pending = <PendingInvite>[];
  Timer? _timer;
  StreamSubscription<void>? _welcomeSub;
  bool _delivering = false;
  bool _started = false;

  /// Armed invites (loaded from [configFile] at [start]).
  List<PendingInvite> get pending => List.unmodifiable(_pending);

  /// Loads persisted invites, hooks welcomes, starts the poller.
  void start() {
    if (_started) return;
    _started = true;
    _pending.addAll(readPendingInvites(configFile));
    _welcomeSub = client.welcomeEvents.listen((_) => check());
    _timer = Timer.periodic(interval, (_) => check());
  }

  /// One delivery pass — poller tick, welcome, or arm time. Runs inside
  /// timers, so errors surface via [onNotice] instead of throwing.
  void check() {
    unawaited(deliver().then(
      (_) {},
      onError: (Object e) =>
          onNotice?.call('[hub] pending invite check failed: $e'),
    ));
  }

  /// The shared delivery engine: one presence snapshot, every pending
  /// whose name matches exactly one online agent (our own id excluded)
  /// gets its chankey DM and leaves the list; a failed DM keeps the
  /// entry for the next pass. Awaitable for deterministic tests.
  Future<void> deliver() async {
    if (_delivering || _pending.isEmpty || !client.connected) return;
    _delivering = true;
    try {
      final agents = await client.presenceQuery();
      for (var i = _pending.length - 1; i >= 0; i--) {
        final invite = _pending[i];
        final match = _soleOnlineMatch(agents, invite.name);
        if (match == null) continue; // away or ambiguous: keep waiting
        try {
          await client.inviteTo(invite.channel, match.agentId);
        } on Object {
          continue; // retried on the next pass
        }
        _pending.removeAt(i);
        await _persist();
        onNotice?.call('invited ${invite.name} to #${invite.channel}');
      }
    } finally {
      _delivering = false;
    }
  }

  /// dap_invite: [nameOrId] is a 16-hex agent id (immediate chankey DM)
  /// or a display name — a currently-online name is invited immediately;
  /// an unknown or offline name arms a pending invite (auto-delivered
  /// when they come online) and the result carries the paste-ready
  /// connect line for the invited user. [channel] defaults to `general`
  /// and is created zero-config under OUR key at arm time.
  Future<InviteResult> invite(String nameOrId, {String? channel}) async {
    final room = channel ?? 'general';
    if (!client.connected) return _failed(room, nameOrId, notConnected);
    if (_idPattern.hasMatch(nameOrId)) return _sendNow(room, nameOrId);
    return _inviteByName(nameOrId, room);
  }

  Future<InviteResult> _inviteByName(String name, String room) async {
    final List<AgentInfo> agents;
    try {
      agents = await client.presenceQuery();
    } on Object catch (e) {
      return _failed(room, name, 'invite failed: $e');
    }
    final matches = _namedMatches(agents, name);
    if (matches.length == 1 && matches.single.online) {
      return _sendNow(room, matches.single.agentId);
    }
    if (matches.length > 1) {
      return _failed(
          room,
          name,
          '"$name" is ambiguous — use an id: '
          '${matches.map((m) => m.agentId).join(', ')}');
    }
    return _arm(name, room); // unknown or offline: invite on arrival
  }

  Future<InviteResult> _sendNow(String channel, String agentId) async {
    try {
      await client.inviteTo(channel, agentId);
    } on Object catch (e) {
      return _failed(channel, agentId, 'invite failed: $e');
    }
    onNotice?.call('invited $agentId to #$channel');
    return (
      ok: true,
      channel: channel,
      to: agentId,
      pending: false,
      connectLine: null,
      error: null,
    );
  }

  /// Arm a pending invite: create the channel under our key (the same
  /// zero-config path as the DM), remember {name, channel} deduped on
  /// (lowercased name, channel), hand back the paste-ready connect line.
  Future<InviteResult> _arm(String name, String channel) async {
    await client.ensureChannelKeys(channel);
    final armed = _pending.any((p) =>
        p.name.toLowerCase() == name.toLowerCase() && p.channel == channel);
    if (!armed) {
      _pending.add(PendingInvite(name: name, channel: channel));
      await _persist();
    }
    check(); // arm-time check: the name may have connected just now
    return (
      ok: true,
      channel: channel,
      to: name,
      pending: true,
      connectLine: 'send to $name:  /dap ${dapHostOf(client.config.url ?? '')}'
          ' $name\n'
          'first connect needs DAP_MASTER_SECRET set (enrolls once, then stored)',
      error: null,
    );
  }

  InviteResult _failed(String channel, String to, String error) => (
        ok: false,
        channel: channel,
        to: to,
        pending: false,
        connectLine: null,
        error: error,
      );

  /// The single online agent displaying [name] case-insensitively, our
  /// own id excluded (shared-config self-invite hazard) — null while the
  /// name is away or ambiguous.
  AgentInfo? _soleOnlineMatch(List<AgentInfo> agents, String name) {
    final wanted = name.toLowerCase();
    final matches = agents
        .where((a) =>
            a.online &&
            a.agentId != client.agentId &&
            (a.name?.toLowerCase() ?? '') == wanted)
        .toList();
    return matches.length == 1 ? matches.single : null;
  }

  List<AgentInfo> _namedMatches(List<AgentInfo> agents, String name) {
    final wanted = name.toLowerCase();
    return agents
        .where((a) => (a.name?.toLowerCase() ?? '') == wanted)
        .toList();
  }

  Future<void> _persist() =>
      persistDapConfig(invites: List.of(_pending), file: configFile);

  Future<void> dispose() async {
    _timer?.cancel();
    await _welcomeSub?.cancel();
  }
}
