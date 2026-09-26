// Regression tests for issue #988 (flutter_agent_harness): a peer on the
// hub roster advertising a malformed `x25519` must never kill the client
// process. Roster entries are PEER-CONTROLLED strings — unpadded base64
// (43 chars, browser/JS clients), percent-encoded padding (`%3D`),
// base64url alphabet, quotes, or outright garbage must all degrade to
// `dhPublicKey: null` + an onNotice, never a FormatException escaping
// the WebSocket frame pump.
library;

import 'dart:async';
import 'dart:convert';

import 'package:fa_hub_client/fa_hub_client.dart';
import 'package:test/test.dart';

import 'fake_hub.dart';

/// A valid 44-char padded base64 x25519 key with the `=` stripped — the
/// exact shape a JS `btoa`-style encoder without padding produces.
String _unpadded(String b64) => b64.replaceAll('=', '');

Future<void> main() async {
  late FakeHub hub;
  setUp(() async {
    hub = FakeHub();
    await hub.start();
  });
  tearDown(() => hub.stop());

  test('unpadded base64 x25519: key recovered by re-padding, no notice',
      () async {
    final notices = <String>[];
    final client = HubClient(
      config: HubConfig(url: hub.url.toString()),
      identity: await HubIdentity.generate(),
      onNotice: notices.add,
    );
    await client.connect();
    addTearDown(client.disconnect);

    hub.injectPeer(
      agentId: 'foreign-js-peer',
      x25519B64: _unpadded(base64Encode(List.filled(32, 9))),
    );

    final roster = await client.presenceQuery();
    final peer = roster.firstWhere((p) => p.agentId == 'foreign-js-peer');
    // The exact crash shape from #988 (43-char unpadded key from a JS
    // client): re-padded and RECOVERED — E2E with the peer still works.
    expect(peer.dhPublicKey?.bytes.length, 32);
    expect(notices.where((n) => n.contains('unusable x25519')), isEmpty);
  }, timeout: const Timeout(Duration(seconds: 10)));

  test('percent-encoded padding and base64url alphabet still decode',
      () async {
    final client = HubClient(
      config: HubConfig(url: hub.url.toString()),
      identity: await HubIdentity.generate(),
    );
    await client.connect();
    addTearDown(client.disconnect);

    // `AAA...%3D` — padded base64 with URI-encoded `=`.
    final padded = base64Encode(List.filled(32, 3)); // ends with '='
    hub.injectPeer(
        agentId: 'pct-peer', x25519B64: '${padded.substring(0, 43)}%3D');
    // `-_` alphabet (base64url), unpadded.
    final urlsafe = padded.replaceAll('+', '-').replaceAll('/', '_');
    hub.injectPeer(
        agentId: 'urlsafe-peer', x25519B64: _unpadded(urlsafe));

    final roster = await client.presenceQuery();
    expect(
        roster.firstWhere((p) => p.agentId == 'pct-peer').dhPublicKey, isNotNull);
    expect(roster.firstWhere((p) => p.agentId == 'urlsafe-peer').dhPublicKey,
        isNotNull);
  }, timeout: const Timeout(Duration(seconds: 10)));

  test('garbage x25519 and quoted garbage degrade to null, never throw',
      () async {
    final notices = <String>[];
    final client = HubClient(
      config: HubConfig(url: hub.url.toString()),
      identity: await HubIdentity.generate(),
      onNotice: notices.add,
    );
    await client.connect();
    addTearDown(client.disconnect);

    hub.injectPeer(agentId: 'garbage-peer', x25519B64: '!!!not-base64!!!');
    hub.injectPeer(
        agentId: 'quoted-peer', x25519B64: '"${base64Encode(List.filled(32, 5))}"');
    // Wrong length: a decodable 16-byte value is not an x25519 key.
    hub.injectPeer(
        agentId: 'short-peer', x25519B64: base64Encode(List.filled(16, 1)));

    final roster = await client.presenceQuery();
    expect(roster.firstWhere((p) => p.agentId == 'garbage-peer').dhPublicKey,
        isNull);
    expect(roster.firstWhere((p) => p.agentId == 'quoted-peer').dhPublicKey,
        isNotNull); // quotes are stripped, inner key is valid
    expect(
        roster.firstWhere((p) => p.agentId == 'short-peer').dhPublicKey, isNull);
    expect(notices.where((n) => n.contains('x25519')).length, greaterThanOrEqualTo(2));
  }, timeout: const Timeout(Duration(seconds: 10)));

  test('malformed presence frame (non-map roster entry) never kills the pump',
      () async {
    final notices = <String>[];
    final client = HubClient(
      config: HubConfig(url: hub.url.toString()),
      identity: await HubIdentity.generate(),
      onNotice: notices.add,
    );
    await client.connect();
    addTearDown(client.disconnect);

    // A hostile/buggy hub pushing junk into the roster list.
    hub.pushFrame(client.agentId!, const {
      'op': 'presence',
      'agents': [42, 'bogus', {'agentId': 7, 'x25519': '%%bad'}],
    });

    await pumpEventQueue();
    expect(client.status().connected, isTrue);
    expect(notices, isNotEmpty);

    // The connection is still fully usable after the junk frame.
    final roster = await client.presenceQuery();
    expect(roster.map((p) => p.agentId), contains(client.agentId));
  }, timeout: const Timeout(Duration(seconds: 10)));

  test('unknown-shape frame throws are contained, later frames still land',
      () async {
    final client = HubClient(
      config: HubConfig(url: hub.url.toString()),
      identity: await HubIdentity.generate(),
      onNotice: (_) {},
    );
    await client.connect();
    addTearDown(client.disconnect);

    // Whatever a future op handler might throw on, the pump must contain it.
    hub.pushFrame(client.agentId!, const {
      'op': 'msg',
      'from': <dynamic>[], // undecodable shape for every msg path
    });
    await pumpEventQueue();
    expect(client.status().connected, isTrue);

    hub.injectPeer(
        agentId: 'after-junk', x25519B64: _unpadded(base64Encode(List.filled(32, 2))));
    final roster = await client.presenceQuery();
    expect(
        roster.firstWhere((p) => p.agentId == 'after-junk').dhPublicKey?.bytes.length,
        32);
    expect(client.status().connected, isTrue);
  }, timeout: const Timeout(Duration(seconds: 10)));
}
