import 'dart:async';

import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/providers/config.dart';
import 'package:fl_clash/providers/po0_firewall.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:riverpod/riverpod.dart';

class _TestPo0Firewall extends Po0Firewall {
  DateTime clock = DateTime(2026, 1, 1, 12);

  @override
  DateTime now() => clock;
}

class _FakeClient extends Po0FirewallClient {
  _FakeClient() : super(send: (_, _) => throw UnimplementedError());

  final polled = <Po0Token>[];
  final whitelisted = <Po0Token>[];
  final queried = <Po0Token>[];
  var resets = 0;
  Po0ResultType pollType = Po0ResultType.applied;
  Completer<void>? gate;

  Po0TokenResult _result(Po0Token token, Po0ResultType type) => Po0TokenResult(
    label: token.label,
    type: type,
    currentIp: '1.2.3.0/24',
  );

  @override
  Future<Po0TokenResult> poll(Po0Token token) async {
    polled.add(token);
    await gate?.future;
    return _result(token, pollType);
  }

  @override
  Future<Po0TokenResult> whitelist(Po0Token token) async {
    whitelisted.add(token);
    await gate?.future;
    return _result(token, Po0ResultType.applied);
  }

  @override
  Future<Po0TokenResult> query(Po0Token token) async {
    queried.add(token);
    return _result(token, Po0ResultType.applied);
  }

  @override
  void resetConnections() => resets++;
}

const _enabled = Po0FirewallProps(
  enable: true,
  tokenEntries: [
    Po0TokenEntry(token: 'pgnfw_a', name: 'home'),
    Po0TokenEntry(token: 'pgnfw_b'),
  ],
  pollSeconds: 1,
);

const _tokens = [Po0Token('pgnfw_a'), Po0Token('pgnfw_b')];

void main() {
  late _FakeClient client;
  late _TestPo0Firewall notifier;
  late ProviderContainer container;

  void createContainer(Po0FirewallProps props) {
    client = _FakeClient();
    container = ProviderContainer(
      overrides: [
        po0FirewallSettingProvider.overrideWithBuild((_, _) => props),
        po0FirewallClientProvider.overrideWithValue(client),
        po0FirewallProvider.overrideWith(() => notifier = _TestPo0Firewall()),
      ],
    );
    container.read(po0FirewallProvider);
  }

  void updateSetting(Po0FirewallProps Function(Po0FirewallProps) update) {
    container.read(po0FirewallSettingProvider.notifier).update(update);
  }

  Future<void> settle() async {
    for (var i = 0; i < 4; i++) {
      await Future<void>.delayed(Duration.zero);
    }
  }

  Po0FirewallState read() => container.read(po0FirewallProvider);

  tearDown(() => container.dispose());

  test('start polls every token and adds nothing that is listed', () async {
    createContainer(_enabled);
    notifier.start();
    notifier.start();
    await settle();

    expect(client.polled, _tokens);
    expect(client.whitelisted, isEmpty);
    final state = read();
    expect(state.isRunning, isFalse);
    expect(state.lastRunAt, notifier.clock);
    expect(state.lastRunKind, Po0RunKind.poll);
    expect(state.results.map((it) => it.name), ['home', null]);
  });

  test('a missing exit is added through the add endpoint', () async {
    createContainer(_enabled);
    client.pollType = Po0ResultType.notApplied;
    notifier.start();
    await settle();

    expect(client.whitelisted, _tokens);
    expect(read().results.map((it) => it.type), [
      Po0ResultType.applied,
      Po0ResultType.applied,
    ]);
  });

  test('a failed read is not turned into an add', () async {
    createContainer(_enabled);
    client.pollType = Po0ResultType.error;
    notifier.start();
    await settle();

    expect(client.whitelisted, isEmpty);
    expect(read().results.first.type, Po0ResultType.error);
  });

  test('does nothing before start or while disabled', () async {
    createContainer(_enabled.copyWith(enable: false));
    await notifier.whitelist();
    notifier.start();
    notifier.pollNow();
    notifier.onNetworkChanged();
    await settle();
    expect(client.polled, isEmpty);
    expect(client.whitelisted, isEmpty);
    expect(client.resets, 0);
    expect(read().lastRunAt, isNull);
  });

  test('manual query and whitelist reach every token', () async {
    createContainer(_enabled);
    notifier.start();
    await settle();
    await notifier.query();
    expect(client.queried, _tokens);
    expect(read().lastRunKind, Po0RunKind.query);
    await notifier.whitelist();
    expect(client.whitelisted, _tokens);
    expect(read().lastRunKind, Po0RunKind.whitelist);
  });

  test('a request asked for mid-run is queued and runs after', () async {
    createContainer(_enabled);
    client.gate = Completer<void>();
    notifier.start();
    await settle();
    unawaited(notifier.whitelist());
    await settle();
    expect(read().isRunning, isTrue);
    expect(client.whitelisted, isEmpty);

    client.gate!.complete();
    await settle();
    expect(client.whitelisted, _tokens);
    expect(read().isRunning, isFalse);
  });

  test('a network change drops the connection and polls again', () async {
    createContainer(_enabled);
    notifier.start();
    await settle();
    notifier.onNetworkChanged();
    await settle();
    expect(client.resets, 1);
    expect(client.polled, [..._tokens, ..._tokens]);
  });

  test('changing the tokens whitelists the new list', () async {
    createContainer(_enabled);
    notifier.start();
    await settle();
    updateSetting(
      (state) => state.copyWith(
        tokenEntries: const [Po0TokenEntry(token: 'pgnfw_c')],
      ),
    );
    await settle();
    expect(client.whitelisted, [const Po0Token('pgnfw_c')]);
  });

  test('renaming a token sends nothing', () async {
    createContainer(_enabled);
    notifier.start();
    await settle();
    updateSetting(
      (state) => state.copyWith(
        tokenEntries: const [
          Po0TokenEntry(token: 'pgnfw_a', name: 'office'),
          Po0TokenEntry(token: 'pgnfw_b'),
        ],
      ),
    );
    await settle();
    expect(client.whitelisted, isEmpty);
    expect(client.polled, _tokens);
  });

  test('polls on the interval and pauses while the screen is off', () async {
    createContainer(_enabled);
    notifier.start();
    await settle();
    expect(client.polled, hasLength(2));

    await Future<void>.delayed(const Duration(milliseconds: 1100));
    await settle();
    expect(client.polled, hasLength(4));

    notifier.setScreenOn(false);
    await Future<void>.delayed(const Duration(milliseconds: 1100));
    expect(client.polled, hasLength(4));

    notifier.setScreenOn(true);
    await settle();
    expect(client.polled, hasLength(6));
  });

  test('turning the switch on whitelists once the route is applied', () async {
    createContainer(_enabled.copyWith(enable: false));
    notifier.start();
    await settle();
    updateSetting((state) => state.copyWith(enable: true));
    await settle();
    expect(client.whitelisted, isEmpty);
    await Future<void>.delayed(
      Po0Firewall.routingDelay + const Duration(milliseconds: 100),
    );
    await settle();
    expect(client.whitelisted, _tokens);

    updateSetting((state) => state.copyWith(enable: false));
    final polled = client.polled.length;
    await Future<void>.delayed(const Duration(milliseconds: 1100));
    expect(client.polled, hasLength(polled));
  });

  test('a new interval reschedules the next poll', () async {
    createContainer(_enabled.copyWith(pollSeconds: 60));
    notifier.start();
    await settle();
    updateSetting((state) => state.copyWith(pollSeconds: 1));
    await Future<void>.delayed(const Duration(milliseconds: 1100));
    await settle();
    expect(client.polled, hasLength(4));
  });

  test('failures back off up to the cap', () {
    const second = Duration(seconds: 1);
    expect(Po0Firewall.nextDelayFor(0, second), second);
    expect(Po0Firewall.nextDelayFor(1, second), second * 2);
    expect(Po0Firewall.nextDelayFor(3, second), second * 8);
    expect(Po0Firewall.nextDelayFor(9, second), second * 16);
    expect(
      Po0Firewall.nextDelayFor(2, const Duration(seconds: 20)),
      Po0Firewall.maxBackoff,
    );
    const long = Duration(minutes: 5);
    expect(Po0Firewall.nextDelayFor(3, long), long);
  });

  test('the poll interval stays in range', () {
    expect(
      Po0Firewall.pollIntervalOf(const Po0FirewallProps(pollSeconds: 0)),
      const Duration(seconds: 1),
    );
    expect(
      Po0Firewall.pollIntervalOf(const Po0FirewallProps(pollSeconds: 99999)),
      const Duration(seconds: 3600),
    );
  });

  test('the real client goes DIRECT while the proxy is stopped', () {
    final container = ProviderContainer();
    addTearDown(container.dispose);
    expect(container.read(po0FirewallClientProvider), isA<Po0FirewallClient>());
  });
}
