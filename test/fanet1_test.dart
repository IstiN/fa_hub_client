import 'dart:convert';
import 'dart:io';

import 'package:cryptography/cryptography.dart';
import 'package:fa_hub_client/fa_hub_client.dart';
import 'package:test/test.dart';

import 'fake_hub.dart';

const _timeout = Timeout(Duration(seconds: 10));

void main() {
  final vectors = _loadVectors();

  group('fa_network fanet1 known-answer vectors', () {
    for (final vector in vectors) {
      final frameId = vector['frameId'] as String;

      test('$frameId: fixed-nonce seal is byte-exact and open round-trips',
          () async {
        final raw = base64Decode(vector['ciphertext'] as String);
        final sealed = await sealFanet1(
          senderIdentity: await _senderKeyPair(vector),
          channelPub: _publicKey(vector['channelPub'] as String),
          frameId: frameId,
          channelId: vector['channelId'] as String,
          plaintext: vector['plaintext'] as String,
          nonce: raw.sublist(0, 12),
        );
        expect(sealed, _expectedFrame(vector));

        final opened = await openFanet1(
          channelKeyPair: await _channelKeyPair(vector),
          frameId: frameId,
          channelId: vector['channelId'] as String,
          payloadB64: sealed,
        );
        expect(opened.plaintext, vector['plaintext']);
        expect(opened.senderPub, vector['senderPub']);
      });

      test('$frameId: wrong frame id and channel id fail authentication',
          () async {
        final channelKeyPair = await _channelKeyPair(vector);
        final payload = _expectedFrame(vector);
        await expectLater(
          openFanet1(
            channelKeyPair: channelKeyPair,
            frameId: '$frameId-rewritten',
            channelId: vector['channelId'] as String,
            payloadB64: payload,
          ),
          throwsA(anything),
        );
        await expectLater(
          openFanet1(
            channelKeyPair: channelKeyPair,
            frameId: frameId,
            channelId: (vector['channelId'] as String).substring(8),
            payloadB64: payload,
          ),
          throwsA(anything),
        );
      });
    }
  });

  group('hub fanet1 interop', () {
    late FakeHub hub;

    setUp(() async {
      hub = FakeHub();
      await hub.start();
    });

    tearDown(() => hub.stop());

    test('repository opens a vector frame as a channel message without whois',
        () async {
      final vector = vectors[1]; // fa app → DAP agent known answer.
      final channel = vector['channelId'] as String;
      final client = await _client(
        hub,
        channels: {channel: vector['channelPub'] as String},
        channelSecrets: {channel: vector['channelPriv'] as String},
      );
      final repository = HubMessagingRepository(client);
      await repository.start();
      addTearDown(repository.dispose);

      final arrived = client.inbound
          .firstWhere((message) => message.id == vector['frameId'])
          .timeout(const Duration(seconds: 5));
      hub.pushMsg(client.agentId!, {
        'from': 'fa_network-relay',
        'id': vector['frameId'],
        'ts': 1700000000000,
        'channel': channel,
        'ciphertext': _expectedFrame(vector),
      });
      final inbound = await arrived;
      expect(inbound.plaintext, vector['plaintext']);

      final drained = await repository.drain('#$channel');
      expect(drained, hasLength(1));
      expect(drained.single.text, vector['plaintext']);
      expect(drained.single.toId, '#$channel');
      expect(hub.whoisQueries, isEmpty);
    }, timeout: _timeout);

    test('fanet1 authentication failure stays loud and opaque', () async {
      final vector = vectors[1];
      final channel = vector['channelId'] as String;
      final client = await _client(
        hub,
        channels: {channel: vector['channelPub'] as String},
        channelSecrets: {channel: vector['channelPriv'] as String},
      );
      final repository = HubMessagingRepository(client);
      await repository.start();
      addTearDown(repository.dispose);

      final rewrittenId = '${vector['frameId']}-rewritten';
      final arrived = client.inbound
          .firstWhere((message) => message.id == rewrittenId)
          .timeout(const Duration(seconds: 5));
      hub.pushMsg(client.agentId!, {
        'from': 'fa_network-relay',
        'id': rewrittenId,
        'ts': 1700000000000,
        'channel': channel,
        'ciphertext': _expectedFrame(vector),
      });
      expect((await arrived).plaintext, isNull);
      final drained = await repository.drain('#$channel');
      expect(
          drained.single.text,
          '[hub] undecryptable message from '
          'fa_network-relay');
    }, timeout: _timeout);

    test('sendChannelFanet1 emits senderX and sendToChannel stays RAW',
        () async {
      final channelKeys = await newChannelKeypair();
      final alice = await _client(hub, channels: {'general': channelKeys.pub});
      final bob = await _client(
        hub,
        channels: {'general': channelKeys.pub},
        channelSecrets: {'general': channelKeys.priv},
      );
      final repository = HubMessagingRepository(bob);
      await alice.connect();
      await repository.start();
      addTearDown(alice.disconnect);
      addTearDown(repository.dispose);

      final fanetArrived = bob.inbound
          .firstWhere((message) => message.plaintext == 'fanet1 hello')
          .timeout(const Duration(seconds: 5));
      await alice.sendChannelFanet1('general', 'fanet1 hello');
      await fanetArrived;

      final fanetWire = hub.relayed.single;
      final fanetPayload = base64Decode(fanetWire['ciphertext'] as String);
      expect(fanetPayload.first, fanet1FrameVersion);
      expect(
        fanetPayload.sublist(1, 33),
        alice.identity.dhPublicKey.bytes,
      );
      expect(
        fanetPayload.length,
        1 + 32 + 12 + 16 + utf8.encode('fanet1 hello').length,
      );
      final opened = await openFanet1(
        channelKeyPair:
            await X25519().newKeyPairFromSeed(base64Decode(channelKeys.priv)),
        frameId: fanetWire['id'] as String,
        channelId: 'general',
        payloadB64: fanetWire['ciphertext'] as String,
      );
      expect(opened.plaintext, 'fanet1 hello');

      final rawArrived = bob.inbound
          .firstWhere((message) => message.plaintext == 'raw dap hello')
          .timeout(const Duration(seconds: 5));
      await alice.sendToChannel('general', 'raw dap hello');
      await rawArrived;
      final rawWire = hub.relayed[1];
      expect(
        base64Decode(rawWire['ciphertext'] as String).length,
        12 + 16 + utf8.encode('raw dap hello').length,
      );
      expect(hub.whoisQueries, contains(alice.agentId));
    }, timeout: _timeout);

    test('repository keeps the legacy RAW dap/1 channel path readable',
        () async {
      final channelKeys = await newChannelKeypair();
      final alice = await _client(hub, channels: {'general': channelKeys.pub});
      final bob = await _client(
        hub,
        channels: {'general': channelKeys.pub},
        channelSecrets: {'general': channelKeys.priv},
      );
      final repository = HubMessagingRepository(bob);
      await alice.connect();
      await repository.start();
      addTearDown(alice.disconnect);
      addTearDown(repository.dispose);

      final arrived = bob.inbound
          .firstWhere((message) => message.plaintext == 'legacy raw')
          .timeout(const Duration(seconds: 5));
      await alice.sendToChannel('general', 'legacy raw');
      await arrived;

      final drained = await repository.drain('#general');
      expect(drained.single.text, 'legacy raw');
      expect(hub.whoisQueries, contains(alice.agentId));
    }, timeout: _timeout);
  });
}

List<Map<String, Object?>> _loadVectors() {
  // Byte-for-byte copy of fa_network/internal/server/testdata/fanet1_vectors.json.
  final decoded = jsonDecode(
    File('test/testdata/fanet1_vectors.json').readAsStringSync(),
  ) as List;
  return [
    for (final vector in decoded) Map<String, Object?>.from(vector as Map),
  ];
}

String _expectedFrame(Map<String, Object?> vector) => base64Encode([
      fanet1FrameVersion,
      ...base64Decode(vector['senderPub'] as String),
      ...base64Decode(vector['ciphertext'] as String),
    ]);

Future<SimpleKeyPair> _senderKeyPair(Map<String, Object?> vector) =>
    X25519().newKeyPairFromSeed(_hexDecode(vector['senderPriv'] as String));

Future<SimpleKeyPair> _channelKeyPair(Map<String, Object?> vector) =>
    X25519().newKeyPairFromSeed(base64Decode(vector['channelPriv'] as String));

SimplePublicKey _publicKey(String bytesB64) =>
    SimplePublicKey(base64Decode(bytesB64), type: KeyPairType.x25519);

Future<HubClient> _client(
  FakeHub hub, {
  Map<String, String> channels = const {},
  Map<String, String> channelSecrets = const {},
}) async =>
    HubClient(
      config: HubConfig(
        url: hub.url.toString(),
        channels: channels,
        channelSecrets: channelSecrets,
      ),
      identity: await HubIdentity.generate(),
    );

List<int> _hexDecode(String hex) => [
      for (var i = 0; i < hex.length; i += 2)
        int.parse(hex.substring(i, i + 2), radix: 16),
    ];
