// Copyright (c) 2026, the Flutter Agent Harness authors.
// Use of this source code is governed by a MIT license that can be found
// in the LICENSE file.

/// Join-denial tracking (issue #1016): master-gated hubs answer a
/// client-secret join of an unknown channel with
/// `access_denied: channel creation requires the master secret`. The
/// client must (a) surface the denial as a `JoinDenied` event,
/// (b) never auto-rejoin that channel on later reconnects, and
/// (c) retry it on an explicit `join()` (an invite may have arrived).
///
/// Observable attempts: the fake hub answers every join attempt on a
/// denied channel with the denial frame (and fires a join event only on
/// success), so denial count == attempt count for denied channels and
/// join events == attempts for granted ones.
library;

import 'dart:async';

import 'package:fa_hub_client/fa_hub_client.dart';
import 'package:test/test.dart';

import 'fake_hub.dart';

const timeout = Timeout(Duration(seconds: 10));
final tinyBackoff = (int _) => const Duration(milliseconds: 5);

Future<void> waitFor(bool Function() condition) =>
    Future.doWhile(() async {
      await Future<void>.delayed(const Duration(milliseconds: 20));
      return !condition();
    }).timeout(const Duration(seconds: 5));

void main() {
  late FakeHub hub;

  setUp(() async {
    hub = FakeHub(joinDenied: {'denied-ch'});
    await hub.start();
  });

  tearDown(() async {
    await hub.stop();
  });

  test(
      'access_denied on join: one attempt, denial event, no retry on '
      'reconnect, explicit join() retries; granted channels unaffected',
      () async {
    // Subscribed BEFORE any connect: hub.joins is a broadcast stream
    // with no buffer, and the joins fire inside connect().
    final joinCounts = <String, int>{};
    final joinWaiters = <String, List<Completer<int>>>{};
    hub.joins.listen((j) {
      final n = (joinCounts[j.channel] ?? 0) + 1;
      joinCounts[j.channel] = n;
      for (final c in joinWaiters.remove(j.channel) ?? <Completer<int>>[]) {
        if (!c.isCompleted) c.complete(n);
      }
    });
    Future<int> waitJoin(String channel, int minCount) async {
      if ((joinCounts[channel] ?? 0) >= minCount) return joinCounts[channel]!;
      final c = Completer<int>();
      (joinWaiters[channel] ??= []).add(c);
      return c.future.timeout(const Duration(seconds: 5));
    }

    final identity = await HubIdentity.generate();
    final client = HubClient(
      config: HubConfig(
        url: hub.url.toString(),
        channels: const {'denied-ch': 'pub-denied', 'granted-ch': 'pub-granted'},
      ),
      identity: identity,
      backoff: tinyBackoff,
    );
    addTearDown(client.disconnect);

    final denials = <JoinDenied>[];
    final sub = client.joinDenials.listen(denials.add);
    addTearDown(sub.cancel);

    await client.connect();

    // The denied channel was attempted exactly once and the denial
    // surfaces with channel/code/msg (the wire error never names the
    // channel — the client FIFO-matches it to the pending join).
    await waitJoin('granted-ch', 1);
    await waitFor(() => denials.isNotEmpty);
    expect(denials, hasLength(1));
    expect(denials.single.channel, 'denied-ch');
    expect(denials.single.code, 'access_denied');
    expect(denials.single.msg, contains('channel creation requires'));

    // Reconnect: a server-side drop drives the client's own retry loop
    // (disconnect()/connect() is NOT a reconnect — disconnect is
    // terminal — so the drop is the honest simulation). After the
    // second welcome the granted channel re-joins, the denied one does
    // NOT retry (no second denial = no second attempt).
    await hub.closeAgent(client.agentId!);
    await waitJoin('granted-ch', 2);
    await Future<void>.delayed(const Duration(milliseconds: 50));
    expect(denials, hasLength(1), reason: 'no retry on reconnect');

    // Explicit join retries even a denied channel — the hub denies it
    // AGAIN (no join event; the second denial event is the signal).
    client.join('denied-ch', 'pub-denied');
    await waitFor(() => denials.length >= 2);
    await Future<void>.delayed(const Duration(milliseconds: 50));
    expect(
      denials,
      hasLength(2),
      reason: 'explicit join retries, denial re-surfaces',
    );
  }, timeout: timeout);
}
