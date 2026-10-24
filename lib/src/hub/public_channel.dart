// Copyright (c) 2026, the Flutter Agent Harness authors.
// Use of this source code is governed by a MIT license that can be found
// in the LICENSE file.

/// Public-channel payload codec (fa_network showcase contract): a PUBLIC
/// channel has NO chankey — the payload is `base64(raw message)`, by app
/// convention a JSON `{"text": …}` wrapper. Foreign producers may send
/// raw utf8, so decoding tolerates both.
///
/// Without this, a DAP/1 client renders every public-channel frame as
/// "undecryptable" (it attempts chankey E2E decryption and fails) and
/// its own encrypted sends are unreadable to showcase members.
library;

import 'dart:convert';

/// Encodes [text] for a public channel: base64 of `{"text": …}`.
String encodePublicChannelText(String text) =>
    base64Encode(utf8.encode(jsonEncode({'text': text})));

/// Decodes a public-channel payload; null when the bytes are not valid
/// base64/utf8 (a tampered or genuinely encrypted frame stays opaque).
String? decodePublicChannelPayload(String payloadB64) {
  if (payloadB64.isEmpty) return null;
  final String raw;
  try {
    raw = utf8.decode(base64Decode(payloadB64));
  } on Object {
    return null;
  }
  try {
    final asJson = jsonDecode(raw);
    if (asJson is Map && asJson['text'] is String) {
      return asJson['text'] as String;
    }
  } on Object {
    // Raw utf8 from a foreign producer — return as-is below.
  }
  return raw;
}
