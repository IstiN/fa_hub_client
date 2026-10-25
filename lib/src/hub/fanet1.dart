/// Self-describing `fanet1` channel frames for fa_network interoperability.
///
/// The AEAD and key schedule are the DAP/1 primitives in `payload_crypto.dart`.
/// A fanet1 frame adds a version and the sender's X25519 public key, so the
/// recipient can decrypt with the channel private key without a hub whois:
///
/// ```
/// base64(0x01 || senderX25519(32) || nonce(12) || ciphertext || tag(16))
/// ```
///
/// The AAD is `dap1|<frameId>|<channelId>` and the HKDF salt is the UTF-8
/// frame id. Relay rewrites of either id therefore fail authentication.
library;

import 'dart:convert';

import 'package:cryptography/cryptography.dart';

import 'payload_crypto.dart';

/// The fanet1 binary frame version.
const fanet1FrameVersion = 0x01;

const _senderKeyLength = 32;
const _nonceLength = 12;
const _tagLength = 16;
const _minFrameLength = 1 + _senderKeyLength + _nonceLength + _tagLength;

/// Whether [payloadB64] has the fanet1 version and minimum frame shape.
///
/// Invalid base64 is not a fanet1 frame. Call [openFanet1] to authenticate
/// and decrypt; this predicate only selects the wire decoder.
bool isFanet1Payload(String payloadB64) {
  try {
    final data = base64Decode(payloadB64);
    return data.length >= _minFrameLength && data.first == fanet1FrameVersion;
  } on Object {
    return false;
  }
}

/// Seals [plaintext] into a self-describing fanet1 channel frame.
///
/// [senderIdentity] and [channelPub] are X25519 keys. [frameId] must be the
/// id carried by the relayed envelope and [channelId] its hub channel id.
/// Omit [nonce] in production; the fixed-nonce seam supports deterministic
/// known-answer vectors.
Future<String> sealFanet1({
  required SimpleKeyPair senderIdentity,
  required SimplePublicKey channelPub,
  required String frameId,
  required String channelId,
  required String plaintext,
  List<int>? nonce,
}) async {
  final rawPayload = await encryptPayload(
    senderDhKeyPair: senderIdentity,
    recipientDhPubkey: channelPub,
    frameId: frameId,
    aadTarget: channelId,
    plaintext: plaintext,
    nonce: nonce,
  );
  final senderPub = await senderIdentity.extractPublicKey();
  return base64Encode([
    fanet1FrameVersion,
    ...senderPub.bytes,
    ...base64Decode(rawPayload),
  ]);
}

/// Opens a fanet1 frame with the channel X25519 [channelKeyPair].
///
/// Returns the authenticated sender public key (base64) and plaintext. Wrong
/// keys, frame ids, channel ids, malformed frames, and tampering all throw;
/// no unauthenticated plaintext is returned.
Future<({String senderPub, String plaintext})> openFanet1({
  required SimpleKeyPair channelKeyPair,
  required String frameId,
  required String channelId,
  required String payloadB64,
}) async {
  final data = base64Decode(payloadB64);
  if (data.length < _minFrameLength) {
    throw const FormatException('fanet1 frame too short');
  }
  if (data.first != fanet1FrameVersion) {
    throw FormatException('unsupported fanet1 frame version ${data.first}');
  }
  final senderPub = SimplePublicKey(
    data.sublist(1, 1 + _senderKeyLength),
    type: KeyPairType.x25519,
  );
  final plaintext = await decryptPayload(
    recipientDhKeyPair: channelKeyPair,
    senderDhPubkey: senderPub,
    frameId: frameId,
    aadTarget: channelId,
    ciphertextB64: base64Encode(data.sublist(1 + _senderKeyLength)),
  );
  return (
    senderPub: base64Encode(senderPub.bytes),
    plaintext: plaintext,
  );
}
