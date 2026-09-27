import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:cryptography/cryptography.dart';
import 'package:fa_hub_client/fa_hub_client.dart';
import 'package:test/test.dart';

import 'fake_hub.dart';

const timeout = Timeout(Duration(seconds: 10));
final tinyBackoff = (int _) => const Duration(milliseconds: 5);

Future<HubClient> connect(FakeHub hub, HubIdentity identity,
    {Map<String, String> channels = const {},
    Map<String, String> channelSecrets = const {},
    Duration Function(int)? backoff}) async {
  final client = HubClient(
    config: HubConfig(
      url: hub.url.toString(),
      channels: channels,
      channelSecrets: channelSecrets,
    ),
    identity: identity,
    backoff: backoff,
  );
  await client.connect();
  return client;
}

void main() {
  late FakeHub hub;

  setUp(() async {
    hub = FakeHub();
    await hub.start();
  });

  tearDown(() async {
    await hub.stop();
  });

  test('hello → welcome handshake; hub verifies the ed25519 signature',
      () async {
    final identity = await HubIdentity.generate();
    final client = await connect(hub, identity);

    // agentId = hex(sha256(ed25519_pubkey_raw))[:16], independently computed
    final digest = await Sha256().hash(identity.signingPublicKey.bytes);
    final expected = digest.bytes
        .map((b) => b.toRadixString(16).padLeft(2, '0'))
        .join()
        .substring(0, 16);
    expect(client.agentId, expected);

    // welcomed => the hub accepted our signed hello
    expect(hub.rejectedHellos, 0);
    expect(client.welcomed, completion(expected));
    await client.disconnect();
  }, timeout: timeout);

  test('hub rejects a hello with a bad signature', () async {
    final identity = await HubIdentity.generate();
    final raw = await WebSocket.connect(hub.url.toString());
    final error = Completer<String>();
    late final StreamSubscription sub;
    sub = raw.listen((dynamic data) {
      final frame = jsonDecode(data as String) as Map;
      if (frame['op'] == 'error') {
        error.complete(frame['code'] as String);
      }
    });
    // hello claiming identity's pubkey but signed by a different key
    final impostor = await Ed25519().newKeyPair();
    final frame = <String, dynamic>{
      'op': 'hello',
      'v': 1,
      'pubkey': identity.signingPubkeyB64,
      'x25519': identity.dhPubkeyB64,
      'nonce': randomHex(16),
      'ts': DateTime.now().millisecondsSinceEpoch,
    };
    frame['sig'] = await signFrame(frame, impostor);
    raw.add(jsonEncode(frame));
    expect(await error.future.timeout(const Duration(seconds: 5)),
        'bad_signature');
    expect(hub.rejectedHellos, 1);
    await sub.cancel();
    await raw.close();
  }, timeout: timeout);

  test('signed channel send is relayed and decryptable by the other member',
      () async {
    final channelKeys = await X25519().newKeyPair();
    final channelPub =
        base64Encode((await channelKeys.extractPublicKey()).bytes);
    final channelPriv =
        base64Encode(await channelKeys.extractPrivateKeyBytes());

    final alice = await connect(hub, await HubIdentity.generate(),
        channels: {'general': channelPub});
    final bob = await connect(hub, await HubIdentity.generate(),
        channels: {'general': channelPub},
        channelSecrets: {'general': channelPriv});

    final received = bob.inbound
        .firstWhere((m) => m.plaintext == 'chan hello')
        .timeout(const Duration(seconds: 5));
    await alice.sendToChannel('general', 'chan hello');
    final msg = await received;

    expect(msg.channel, 'general');
    expect(msg.from, alice.agentId);
    expect(hub.deliveredTo, [bob.agentId]); // sender not echoed
    // hub routed ciphertext only
    expect(jsonEncode(hub.relayed.single), isNot(contains('chan hello')));

    await alice.disconnect();
    await bob.disconnect();
  }, timeout: timeout);

  test('sendChannelEnvelope: caller-sealed payload rides the wire with the '
      'frame id handed to the seal callback', () async {
    final channelKeys = await X25519().newKeyPair();
    final channelPub =
        base64Encode((await channelKeys.extractPublicKey()).bytes);

    final alice = await connect(hub, await HubIdentity.generate(),
        channels: {'general': channelPub});
    final bob = await connect(hub, await HubIdentity.generate(),
        channels: {'general': channelPub});

    String? sealedWithId;
    final delivered = bob.inbound.first.timeout(const Duration(seconds: 5));
    await alice.sendChannelEnvelope('general', (frameId) async {
      sealedWithId = frameId;
      // Self-describing fanet1-style frame: version byte + opaque payload
      // (the hub must relay it byte-identically).
      return base64Encode([0x01, ...utf8.encode('caller-sealed')]);
    });
    await delivered;

    final wire = hub.relayed.single;
    expect(wire['channel'], 'general');
    expect(wire['id'], sealedWithId,
        reason: 'the seal callback must receive the frame id on the wire');
    expect(base64Decode(wire['ciphertext'] as String).first, 0x01);
    expect(utf8.decode(base64Decode(wire['ciphertext'] as String).sublist(1)),
        'caller-sealed');
    expect(wire['sig'], isA<String>());

    await alice.disconnect();
    await bob.disconnect();
  }, timeout: timeout);

  test('DM round-trip: whois first, then E2E decrypt on the recipient',
      () async {
    final alice =
        await connect(hub, await HubIdentity.generate(), backoff: tinyBackoff);
    final bob = await connect(hub, await HubIdentity.generate());

    final received = bob.inbound
        .firstWhere((m) => m.plaintext == 'secret dm')
        .timeout(const Duration(seconds: 5));
    await alice.sendDm(bob.agentId!, 'secret dm');
    final msg = await received;

    expect(msg.from, alice.agentId);
    expect(msg.channel, isNull);
    expect(hub.deliveredTo, [bob.agentId]); // DM reaches recipient only
    expect(hub.whoisQueries, contains(bob.agentId)); // whois before first DM
    expect(jsonEncode(hub.relayed.single), isNot(contains('secret dm')));

    await alice.disconnect();
    await bob.disconnect();
  }, timeout: timeout);

  test('reconnect: re-hello and flush re-receives the queued DM', () async {
    final alice =
        await connect(hub, await HubIdentity.generate(), backoff: tinyBackoff);
    final bob = await connect(hub, await HubIdentity.generate());

    // Drop alice's connection hub-side, wait until the hub sees her offline.
    final offline = hub.agentOffline
        .firstWhere((id) => id == alice.agentId)
        .timeout(const Duration(seconds: 5));
    await hub.closeAgent(alice.agentId!);
    await offline;

    // While alice is offline, bob DMs her → hub queues it in her mailbox.
    await bob.sendDm(alice.agentId!, 'queued while away');

    // Alice reconnects on her own (5 ms backoff), re-hellos, and flushes.
    final queued = alice.inbound
        .firstWhere((m) => m.plaintext == 'queued while away')
        .timeout(const Duration(seconds: 5));
    await hub.waitForHellos(3); // alice initial + bob + alice re-hello
    final msg = await queued;

    expect(msg.from, bob.agentId);
    expect(hub.rejectedHellos, 0);
    expect(hub.deliveredTo, isEmpty); // never delivered live: queued path

    await alice.disconnect();
    await bob.disconnect();
  }, timeout: timeout);

  test('presence query lists connected agents', () async {
    final alice = await connect(hub, await HubIdentity.generate());
    final bob = await connect(hub, await HubIdentity.generate());

    final agents = await bob.presenceQuery();
    expect(
      agents.map((a) => a.agentId),
      containsAll([alice.agentId, bob.agentId]),
    );
    expect(
      agents.firstWhere((a) => a.agentId == alice.agentId).dhPublicKey,
      isNotNull,
    );

    await alice.disconnect();
    await bob.disconnect();
  }, timeout: timeout);

  test('presence lastSeen parses to a UTC DateTime and survives asSelf',
      () async {
    final alice = await connect(hub, await HubIdentity.generate());
    final floor = DateTime.now().toUtc().subtract(const Duration(seconds: 5));

    final agents = await alice.presenceQuery();
    final seen = agents.firstWhere((a) => a.agentId == alice.agentId).lastSeen;
    expect(seen, isNotNull);
    expect(seen!.isUtc, isTrue);
    expect(seen.isAfter(floor), isTrue);

    // asSelf keeps the hub-reported activity (peers() self entry).
    final self = (await alice.peers()).firstWhere(
      (p) => p.agentId == alice.agentId,
    );
    expect(self.lastSeen, isNotNull);

    await alice.disconnect();
  }, timeout: timeout);

  test('legacy hub: roster without lastSeen parses to null', () async {
    hub.emitLastSeen = false; // wire `omitempty` on pre-0.3.1 hubs
    final alice = await connect(hub, await HubIdentity.generate());

    final agents = await alice.presenceQuery();
    expect(
      agents.firstWhere((a) => a.agentId == alice.agentId).lastSeen,
      isNull,
    );

    await alice.disconnect();
  }, timeout: timeout);

  test('status: connected, identity, url, known channels, counters', () async {
    final client = HubClient(
      config: HubConfig(url: hub.url.toString(), channels: {'general': 'AA'}),
      identity: await HubIdentity.generate(),
      backoff: tinyBackoff,
    );

    // Before connecting: honest offline snapshot, channels already known.
    final before = client.status();
    expect(before.connected, isFalse);
    expect(before.agentId, isNull);
    expect(before.name, isNull);
    expect(before.url, hub.url.toString());
    expect(before.channels, ['general']);
    expect(before.hellos, 0);
    expect(before.welcomes, 0);

    await client.connect();
    final status = client.status();
    expect(status.connected, isTrue);
    expect(status.agentId, client.agentId);
    expect(status.url, hub.url.toString());
    expect(status.channels, ['general']);
    expect(status.hellos, 1); // one connection attempt so far
    expect(status.welcomes, 1); // and it was accepted

    await client.disconnect();
    final after = client.status();
    expect(after.connected, isFalse); // disconnect() is synchronous truth
    expect(after.agentId, client.agentId); // identity survives the drop
    expect(after.hellos, 1); // disconnect() disarms the reconnect loop
  }, timeout: timeout);

  test('peers: online-only list, our own entry marked self', () async {
    final client = await connect(hub, await HubIdentity.generate());
    final peer = await connect(hub, await HubIdentity.generate());
    final ghost = await connect(hub, await HubIdentity.generate());
    final ghostGone = hub.agentOffline.firstWhere((id) => id == ghost.agentId);
    await ghost.disconnect(); // registered but gone → offline in presence
    await ghostGone; // hub cleaned up its connection row

    final peers = await client.peers();
    expect(peers.map((p) => p.agentId),
        unorderedEquals([client.agentId, peer.agentId]));
    final self = peers.firstWhere((p) => p.agentId == client.agentId);
    expect(self.self, isTrue);
    expect(self.online, isTrue);
    expect(peers.firstWhere((p) => p.agentId == peer.agentId).self, isFalse);

    await client.disconnect();
    await peer.disconnect();
  }, timeout: timeout);

  test('peers: drops offline agents the raw roster still lists', () async {
    final client = await connect(hub, await HubIdentity.generate());
    final ghost = await connect(hub, await HubIdentity.generate());
    final ghostGone = hub.agentOffline.firstWhere((id) => id == ghost.agentId);
    await ghost.disconnect();
    await ghostGone; // roster query must see the post-cleanup registry

    final roster = await client.presenceQuery();
    expect(roster.map((p) => p.agentId), contains(ghost.agentId));
    expect(
        roster.firstWhere((p) => p.agentId == ghost.agentId).online, isFalse);
    expect((await client.peers()).map((p) => p.agentId),
        isNot(contains(ghost.agentId)));

    await client.disconnect();
  }, timeout: timeout);

  test(
      'retarget/connectTo: bare host + name + room → second welcome, '
      'new agentId, lobby joined, retired loop stays retired', () async {
    final hub2 = FakeHub();
    await hub2.start();
    addTearDown(() => hub2.stop());
    final home = await Directory.systemTemp.createTemp('fah-dap-conn-');
    addTearDown(() => home.delete(recursive: true));

    final client = HubClient(
      config: HubConfig(url: hub.url.toString()),
      identity: await HubIdentity.generate(),
      channelStore: await ChannelStore.fromFile('${home.path}/channels.json'),
      // long enough that retarget lands while the loop parks in backoff —
      // CI runners are slow (keygen + handshake can exceed 400ms), which
      // once let the parked loop reconnect before retirement (welcome #3)
      backoff: (int _) => const Duration(seconds: 3),
    );
    await client.connect();
    final firstId = client.agentId!;
    expect(hub.hellosSeen, 1);

    // network drop → the reconnect loop parks in its 3 s backoff
    await hub.closeAgent(firstId);
    await Future<void>.delayed(const Duration(milliseconds: 80));

    // subscribe early — the lobby join fires during connectTo itself
    final lobbyJoin = hub2.joins
        .firstWhere((j) => j.channel == 'lobby')
        .timeout(const Duration(seconds: 5));

    // bare host: no scheme, no path — normalized to ws://<host>/ws
    final result = await client.connectTo('127.0.0.1:${hub2.url.port}',
        name: 'bee', channel: 'lobby', home: home.path);
    expect(result.ok, isTrue);
    expect(result.url, hub2.url.toString());
    expect(result.name, 'bee');
    expect(result.agentId, isNot(firstId)); // new name = new identity
    expect(result.agentId, client.agentId); // recomputed from the new keys
    expect(result.channels, contains('lobby'));
    expect(client.status().welcomes, 2); // the second welcome
    expect(client.status().url, hub2.url.toString());

    final join = await lobbyJoin;
    expect(join.agentId, result.agentId); // lobby joined under the new id

    // name-derived key file, 0600, reloads to the same identity
    final keyFile = File('${home.path}/.dap/keys/fah/bee.key');
    expect((await keyFile.stat()).modeString(), 'rw-------');
    expect((await HubIdentity.load(keyFile.path)).agentId, result.agentId);

    // the retired loop must never re-hello even after its backoff elapses:
    // wait past the 3s window, then both hubs and the welcome counter must
    // show exactly one hello/welcome each — a rogue loop bumps one of them
    await Future<void>.delayed(const Duration(milliseconds: 3300));
    expect(hub.hellosSeen, 1); // old loop would re-hello the OLD hub
    expect(hub2.hellosSeen, 1);
    expect(client.status().welcomes, 2);

    await client.disconnect();
  }, timeout: timeout);
}
