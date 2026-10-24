import 'dart:convert';

import 'package:fa_hub_client/fa_hub_client.dart';
import 'package:test/test.dart';

void main() {
  test('encode/decode round-trips the app JSON convention', () {
    final encoded = encodePublicChannelText('привет, канал! 👋');
    expect(decodePublicChannelPayload(encoded), 'привет, канал! 👋');
    expect(jsonDecode(utf8.decode(base64Decode(encoded))), {
      'text': 'привет, канал! 👋',
    });
  });

  test('raw utf8 from a foreign producer is tolerated', () {
    final encoded = base64Encode(utf8.encode('plain raw message'));
    expect(decodePublicChannelPayload(encoded), 'plain raw message');
  });

  test('garbage stays opaque (null), never throws', () {
    expect(decodePublicChannelPayload('!!!not-base64!!!'), isNull);
    expect(decodePublicChannelPayload(''), isNull);
    // Valid base64 of an encrypted blob is NOT valid utf8 → opaque.
    expect(
        decodePublicChannelPayload(base64Encode([0xff, 0xfe, 0xfd])), isNull);
  });
}
