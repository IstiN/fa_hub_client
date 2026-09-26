// Regression test for the second #988 crash shape: 'Bad state:
// connection closed'. A server dropping the socket right after the
// upgrade made _abandon completeError() the welcome completer BEFORE
// _cycle reached `await welcomed.future` — the error then had no
// listener and killed the host process as an unhandled zone error (one
// per reconnect attempt). The completer's future now carries .ignore():
// the unawaited case is silenced, the awaiter still sees the error.
library;

import 'dart:async';
import 'dart:io';

import 'package:fa_hub_client/fa_hub_client.dart';
import 'package:test/test.dart';

void main() {
  test('server closing right after the upgrade: nothing reaches the zone, '
      'the client keeps retrying', () async {
    final server = await HttpServer.bind('127.0.0.1', 0);
    addTearDown(() => server.close(force: true));
    server.listen((req) async {
      final ws = await WebSocketTransformer.upgrade(req);
      await ws.close(); // die before any hello is read
    });

    final unhandled = <Object>[];
    final client = HubClient(
      config: HubConfig(url: 'ws://127.0.0.1:${server.port}/ws'),
      identity: await HubIdentity.generate(),
      backoff: (_) => const Duration(milliseconds: 5),
    );
    // Fire-and-forget connect: the error path of the RETURNED future is
    // the caller's to handle — here (and in CI runners) it is ignored.
    client.connect().ignore();
    await Future<void>.delayed(const Duration(milliseconds: 400));

    expect(unhandled, isEmpty,
        reason: 'a pre-welcome drop must stay inside the reconnect loop');
    expect(client.status().hellos, greaterThan(1),
        reason: 'the loop retried instead of dying');

    await client.disconnect();
  }, timeout: const Timeout(Duration(seconds: 5)));
}
