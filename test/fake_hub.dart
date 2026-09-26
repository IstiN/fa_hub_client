/// In-memory DAP/1 hub for tests: HttpServer + WebSocketTransformer on
/// 127.0.0.1 ephemeral port. Implements hello (independent per-spec
/// signature + ts-freshness + nonce-replay checks), welcome, eviction,
/// channel fan-out, DM routing, join, offline mailboxes, flush, whois,
/// presence.
///
/// Signature verification here is deliberately re-implemented (not shared
/// with the client library) so wire-format bugs cannot cancel out.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:cryptography/cryptography.dart';

class FakeHub {
  FakeHub({this.masterSecret, Set<String>? silentOps, Set<String>? errorOps})
      : silentOps = silentOps ?? <String>{},
        errorOps = errorOps ?? <String>{};

  /// When set, every `/ws` dial needs `Authorization: Bearer <token>`
  /// with either the master secret or the issued client secret — a
  /// rejected dial gets HTTP 401 before the upgrade (hub contract).
  final String? masterSecret;

  /// Ops answered with NOTHING (request-hang simulation: the caller
  /// waits until its timeout).
  final Set<String> silentOps;

  /// Ops answered with an `error` frame instead of the normal reply
  /// (error-door tests).
  final Set<String> errorOps;

  /// Client secret issued by the last accepted enroll (bound to
  /// [issuedName]); a re-enroll replaces it — the old secret then 401s.
  String? issuedSecret;
  String? issuedName;
  int enrollCount = 0;

  /// `Authorization` header of every `/ws` dial (bearer-header capture).
  final dialAuths = <String?>[];

  final _enrollEvents = StreamController<String>.broadcast();

  /// Fires with the issued secret for every accepted enroll.
  Stream<String> get enrollments => _enrollEvents.stream;

  final _random = Random();

  HttpServer? _server;

  /// Persistent agent registry (survives disconnects, like presence).
  final _registry = <String, _RegistryEntry>{};

  /// Live connections per agentId (one per agent).
  final _conns = <String, WebSocket>{};
  final _mailboxes = <String, List<Map<String, dynamic>>>{};
  final _nonces = <String>{};
  final _helloEvents = StreamController<String>.broadcast();
  int _hellosSeen = 0;

  /// False emulates a legacy hub whose presence roster omits `lastSeen`
  /// (wire `omitempty`): clients must parse the absent key as null.
  bool emitLastSeen = true;

  int get hellosSeen => _hellosSeen;

  int rejectedHellos = 0;
  final List<Map<String, dynamic>> relayed = [];
  final List<String> whoisQueries = [];
  final List<String> deliveredTo = [];
  final _offlineEvents = StreamController<String>.broadcast();
  final _joinEvents = StreamController<HubJoin>.broadcast();

  /// Channel membership per spec § join (first join creates the channel).
  final channelMembers = <String, Set<String>>{};

  /// Fires for every accepted join (deterministic test waits).
  Stream<HubJoin> get joins => _joinEvents.stream;

  /// Fires when a live connection for an agent goes away.
  Stream<String> get agentOffline => _offlineEvents.stream;

  /// Force-closes an agent's live connection (network-drop simulation).
  Future<void> closeAgent(String agentId) async {
    final ws = _conns[agentId];
    if (ws != null) await ws.close();
  }

  /// Pushes a raw hub `error` frame to an agent's live connection
  /// (error-surfacing tests).
  void pushError(String agentId, String code, String msg) {
    final ws = _conns[agentId];
    if (ws != null) _reply(ws, {'op': 'error', 'code': code, 'msg': msg});
  }

  /// Pushes a raw hub `msg` frame to an agent's live connection
  /// (undecryptable-payload delivery tests).
  void pushMsg(String agentId, Map<String, dynamic> msg) {
    final ws = _conns[agentId];
    if (ws != null) _reply(ws, {'op': 'msg', ...msg});
  }

  /// Pushes an ARBITRARY frame verbatim to an agent's live connection —
  /// hostile/buggy-hub simulations the client must survive.
  void pushFrame(String agentId, Map<String, dynamic> frame) {
    final ws = _conns[agentId];
    if (ws != null) _reply(ws, frame);
  }

  /// Seeds the persistent registry with a foreign peer whose `x25519`
  /// string is VERBATIM (malformed-shape tests: unpadded base64,
  /// percent-encoded padding, garbage — the roster is peer-controlled).
  void injectPeer({
    required String agentId,
    required String x25519B64,
    String? name,
  }) {
    _registry[agentId] = _RegistryEntry(
      pubkeyB64: base64Encode(List.filled(32, 1)),
      x25519B64: x25519B64,
      name: name,
      lastSeenMs: DateTime.now().millisecondsSinceEpoch,
    );
  }

  Stream<String> get hellos => _helloEvents.stream;

  Future<void> start() async {
    _server = await HttpServer.bind('127.0.0.1', 0);
    unawaited(_serve());
  }

  Uri get url => Uri.parse('ws://127.0.0.1:${_server!.port}/ws');

  Future<void> stop() async {
    for (final ws in _conns.values) {
      await ws.close();
    }
    await _helloEvents.close();
    await _offlineEvents.close();
    await _joinEvents.close();
    await _enrollEvents.close();
    await _server?.close(force: true);
  }

  /// Resolves when the hub has seen [n] signature-verified hellos.
  Future<void> waitForHellos(int n) async {
    if (_hellosSeen >= n) return;
    await hellos
        .firstWhere((_) => _hellosSeen >= n)
        .timeout(const Duration(seconds: 5));
  }

  Future<void> _serve() async {
    await for (final request in _server!) {
      if (request.uri.path == '/healthz') {
        request.response.statusCode = 200;
        await request.response.close();
      } else if (request.uri.path == '/ws' &&
          WebSocketTransformer.isUpgradeRequest(request)) {
        final auth = request.headers.value(HttpHeaders.authorizationHeader);
        dialAuths.add(auth);
        final token = _bearer(auth);
        if (masterSecret != null &&
            token != masterSecret &&
            token != issuedSecret) {
          request.response.statusCode = HttpStatus.unauthorized;
          request.response.write('unauthorized');
          await request.response.close();
        } else {
          final ws = await WebSocketTransformer.upgrade(request);
          unawaited(_handle(ws, token));
        }
      } else {
        request.response.statusCode = 404;
        await request.response.close();
      }
    }
  }

  Future<void> _handle(WebSocket ws, String? token) async {
    String? agentId;
    try {
      await for (final Object data in ws) {
        final frame =
            (jsonDecode(data as String) as Map).cast<String, dynamic>();
        if (frame['t'] == 'enroll') {
          _enroll(ws, agentId, token);
          continue;
        }
        final op = frame['op'] as String?;
        if (silentOps.contains(op)) continue; // hang the door: no answer
        if (errorOps.contains(op)) {
          _reply(ws, {
            'op': 'error',
            'code': 'unsupported_op',
            'msg': 'fake hub rejects $op',
          });
          continue;
        }
        switch (op) {
          case 'hello':
            agentId = await _hello(ws, frame, token);
          case 'whois':
            _whois(ws, frame);
          case 'send' when agentId != null:
            await _send(ws, agentId, frame);
          case 'join' when agentId != null:
            _join(ws, agentId, frame);
          case 'flush' when agentId != null:
            _flush(ws, agentId);
          case 'presence_query':
            _presence(ws, frame);
          default:
            _reply(ws, {'op': 'error', 'code': 'bad_frame', 'msg': 'op?$op'});
        }
      }
    } on Object {
      // socket error — fall through to cleanup
    }
    if (agentId != null && identical(_conns[agentId], ws)) {
      _conns.remove(agentId);
      if (!_offlineEvents.isClosed) _offlineEvents.add(agentId);
    }
  }

  Future<String?> _hello(
    WebSocket ws,
    Map<String, dynamic> frame,
    String? token,
  ) async {
    final verdict = await _checkHello(frame);
    if (verdict != null) {
      rejectedHellos++;
      _reply(ws, {'op': 'error', 'code': verdict, 'msg': verdict});
      await ws.close();
      return null;
    }
    // Client-secret connections are bound to the enrolling hello name
    // (hub contract): a different name on that secret is rejected.
    if (token == issuedSecret &&
        issuedName != null &&
        frame['name'] != issuedName) {
      rejectedHellos++;
      _reply(ws, {
        'op': 'error',
        'code': 'name_mismatch',
        'msg': 'client secret is bound to "$issuedName"',
      });
      await ws.close();
      return null;
    }
    final pubkeyB64 = frame['pubkey'] as String;
    final agentId = await _agentIdFor(pubkeyB64);
    final old = _conns[agentId];
    if (old != null && !identical(old, ws)) {
      unawaited(old.close()); // one connection per agent: evict
    }
    _registry[agentId] = _RegistryEntry(
      pubkeyB64: pubkeyB64,
      x25519B64: frame['x25519'] as String? ?? '',
      name: frame['name'] as String?,
      lastSeenMs: DateTime.now().millisecondsSinceEpoch,
    );
    _conns[agentId] = ws;
    _hellosSeen++;
    if (!_helloEvents.isClosed) _helloEvents.add(agentId);
    _reply(ws, {
      'op': 'welcome',
      'agentId': agentId,
    });
    return agentId;
  }

  /// `Bearer <token>` → token (null when the header is absent/malformed).
  static String? _bearer(String? header) => header == null
      ? null
      : RegExp('^Bearer (.+)\$', caseSensitive: false)
          .firstMatch(header)
          ?.group(1);

  /// `{"t":"enroll"}` — master-authenticated, post-hello conns only.
  /// Issues a base64url 32-byte client secret bound to the hello name;
  /// a re-enroll replaces the previous secret (old secret then 401s).
  void _enroll(WebSocket ws, String? agentId, String? token) {
    if (token != masterSecret || agentId == null) {
      _reply(ws, {
        't': 'error',
        'code': 'unauthorized',
        'msg': 'enroll needs a master-authenticated connection after hello',
      });
      return;
    }
    issuedSecret =
        base64Url.encode(List<int>.generate(32, (_) => _random.nextInt(256)));
    issuedName = _registry[agentId]?.name;
    enrollCount++;
    if (!_enrollEvents.isClosed) _enrollEvents.add(issuedSecret!);
    _reply(ws, {'t': 'enrolled', 'secret': issuedSecret});
  }

  /// null = accepted, otherwise the error code.
  Future<String?> _checkHello(Map<String, dynamic> frame) async {
    final ts = frame['ts'];
    if (ts is! int) return 'bad_frame';
    final skew = (DateTime.now().millisecondsSinceEpoch - ts).abs();
    if (skew > 300 * 1000) return 'stale_ts';
    final nonce = frame['nonce'] as String?;
    if (nonce == null || nonce.length < 16) return 'bad_frame';
    if (_nonces.contains(nonce)) return 'replayed_nonce';
    if (!await _verifySig(frame, frame['pubkey'] as String))
      return 'bad_signature';
    _nonces.add(nonce);
    return null;
  }

  /// Independent canonical-JSON signature check per docs/protocol.md.
  /// [signerPubkeyB64] is the hello frame's own `pubkey`, or the
  /// connection's registered key for authenticated ops like `send`.
  Future<bool> _verifySig(
    Map<String, dynamic> frame,
    String signerPubkeyB64,
  ) async {
    final sigB64 = frame['sig'];
    if (sigB64 is! String) return false;
    final unsigned = Map<String, dynamic>.from(frame)..remove('sig');
    final canonical = _canonicalJson(unsigned);
    final digest = await Sha256().hash(utf8.encode(canonical));
    final payload = 'dap1|${frame['op']}|${frame['ts']}|${_hex(digest.bytes)}';
    final publicKey = SimplePublicKey(
      base64Decode(signerPubkeyB64),
      type: KeyPairType.ed25519,
    );
    return Ed25519().verify(
      utf8.encode(payload),
      signature: Signature(base64Decode(sigB64), publicKey: publicKey),
    );
  }

  static String _canonicalJson(Object? value) {
    if (value is Map) {
      final keys = value.keys.map((k) => k.toString()).toList()..sort();
      return '{${keys.map((k) => '"$k":${_canonicalJson(value[k])}').join(',')}}';
    }
    if (value is List) return '[${value.map(_canonicalJson).join(',')}]';
    return jsonEncode(value);
  }

  static Future<String> _agentIdFor(String pubkeyB64) async {
    final digest = await Sha256().hash(base64Decode(pubkeyB64));
    return _hex(digest.bytes).substring(0, 16);
  }

  static String _hex(List<int> bytes) =>
      bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

  void _whois(WebSocket ws, Map<String, dynamic> frame) {
    final target = frame['agentId'] as String;
    whoisQueries.add(target);
    final entry = _registry[target];
    if (entry == null) {
      _reply(ws, {
        'op': 'error',
        'code': 'unknown_agent',
        'msg': 'no agent $target',
      });
      return;
    }
    _reply(ws, {
      'op': 'agent_info',
      'agentId': target,
      'pubkey': entry.pubkeyB64,
      'x25519': entry.x25519B64,
      if (entry.name != null) 'name': entry.name,
      'online': _conns.containsKey(target),
    });
  }

  Future<void> _send(
    WebSocket ws,
    String fromAgentId,
    Map<String, dynamic> frame,
  ) async {
    if (!_conns.containsKey(fromAgentId)) {
      _reply(ws,
          {'op': 'error', 'code': 'not_authenticated', 'msg': 'hello first'});
      return;
    }
    if (!await _verifySig(frame, _registry[fromAgentId]!.pubkeyB64)) {
      _reply(ws, {'op': 'error', 'code': 'bad_signature', 'msg': 'bad sig'});
      return;
    }
    relayed.add(frame);
    final msg = {
      'op': 'msg',
      'from': fromAgentId,
      'id': frame['id'],
      'ts': frame['ts'],
      'ciphertext': frame['ciphertext'],
      if (frame['channel'] != null) 'channel': frame['channel'],
      if (frame['to'] != null) 'to': frame['to'],
    };
    final channel = frame['channel'] as String?;
    if (channel != null) {
      for (final entry in _conns.entries) {
        if (!identical(entry.value, ws)) {
          deliveredTo.add(entry.key);
          _reply(entry.value, msg);
        }
      }
    } else {
      final to = frame['to'] as String;
      final target = _conns[to];
      if (target != null) {
        deliveredTo.add(to);
        _reply(target, msg);
      } else {
        _mailboxes.putIfAbsent(to, () => []).add(msg);
      }
    }
  }

  void _join(WebSocket ws, String agentId, Map<String, dynamic> frame) {
    final channel = frame['channel'] as String;
    channelMembers.putIfAbsent(channel, () => {}).add(agentId);
    if (!_joinEvents.isClosed) {
      _joinEvents.add(HubJoin(agentId: agentId, channel: channel));
    }
    _reply(ws, {'op': 'joined', 'channel': channel});
  }

  void _flush(WebSocket ws, String agentId) {
    final queued = _mailboxes.remove(agentId) ?? const <Map<String, dynamic>>[];
    for (final msg in queued) {
      _reply(ws, msg);
    }
    _reply(ws, {'op': 'flushed', 'count': queued.length});
  }

  void _presence(WebSocket ws, [Map<String, dynamic>? query]) {
    _reply(ws, {
      'op': 'presence',
      // Echo the query's frame id (protocol §presence): the 0.2.x client
      // matches answers to waiters by `replyTo`; without the echo it falls
      // back to the legacy one-completes-all path, where a stale warm-up
      // answer can complete a later query with a pre-disconnect roster
      // (the "peers: online-only always" flake).
      if (query?['id'] case final id?) 'replyTo': id,
      'agents': [
        for (final entry in _registry.entries)
          {
            'agentId': entry.key,
            'name': entry.value.name,
            'online': _conns.containsKey(entry.key),
            'x25519': entry.value.x25519B64,
            if (emitLastSeen) 'lastSeen': entry.value.lastSeenMs,
          },
      ],
    });
  }

  void _reply(WebSocket ws, Map<String, dynamic> frame) {
    if (ws.readyState == WebSocket.open) ws.add(jsonEncode(frame));
  }
}

class _RegistryEntry {
  _RegistryEntry({
    required this.pubkeyB64,
    required this.x25519B64,
    this.name,
    required this.lastSeenMs,
  });

  final String pubkeyB64;
  final String x25519B64;
  final String? name;

  /// Hub wall-clock ms of the agent's last accepted hello (fake stand-in
  /// for the real hub's last-authenticated-inbound-frame tracking).
  final int lastSeenMs;
}

/// One accepted `join` (spec § join).
class HubJoin {
  HubJoin({required this.agentId, required this.channel});

  final String agentId;
  final String channel;
}
