import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/providers/po0_firewall.dart';
import 'package:fl_clash/providers/providers.dart';
import 'package:fl_clash/state.dart';
import 'package:fl_clash/views/po0_firewall.dart';
import 'package:material_ui/material_ui.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';

import '../helpers/test_app.dart';

class _IdleFirewall extends Po0Firewall {
  _IdleFirewall(this.initial);

  final Po0FirewallState initial;

  @override
  Po0FirewallState build() => initial;

  @override
  Future<void> query() async {}

  @override
  Future<void> whitelist() async {}
}

void main() {
  late ProviderContainer container;

  Po0FirewallProps setting() => container.read(po0FirewallSettingProvider);

  Future<void> pumpView(
    WidgetTester tester, {
    Po0FirewallProps props = defaultPo0FirewallProps,
    Po0FirewallState state = const Po0FirewallState(),
  }) async {
    tester.view.physicalSize = const Size(1000, 1600);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    container = ProviderContainer(
      overrides: [
        po0FirewallSettingProvider.overrideWithBuild((_, _) => props),
        po0FirewallProvider.overrideWith(() => _IdleFirewall(state)),
      ],
    );
    addTearDown(container.dispose);
    globalState.container = container;
    container
        .read(viewSizeProvider.notifier)
        .update((_) => const Size(1000, 1600));

    await tester.pumpWidget(
      UncontrolledProviderScope(
        container: container,
        child: const TestApp(child: Po0FirewallView()),
      ),
    );
    await tester.pumpAndSettle();
  }

  testWidgets('shows the empty list and toggles the switch', (tester) async {
    await pumpView(tester);
    final l10n = currentAppLocalizations;

    expect(find.text(l10n.po0TokensEmpty), findsOneWidget);
    await tester.tap(find.text(l10n.po0AutoWhitelist));
    await tester.pumpAndSettle();
    expect(setting().enable, isTrue);
  });

  testWidgets('adds a token and rejects an invalid one', (tester) async {
    await pumpView(tester);
    final l10n = currentAppLocalizations;

    await tester.tap(find.byTooltip(l10n.po0AddToken));
    await tester.pumpAndSettle();
    final fields = find.byType(EditableText);
    await tester.enterText(fields.first, 'bad');
    await tester.tap(find.text(l10n.confirm));
    await tester.pumpAndSettle();
    expect(find.text(l10n.po0TokenInvalid), findsOneWidget);
    expect(setting().tokenEntries, isEmpty);

    await tester.enterText(fields.first, 'pgnfw_abcdef');
    await tester.enterText(fields.last, 'home');
    await tester.tap(find.text(l10n.confirm));
    await tester.pumpAndSettle();
    expect(setting().tokenEntries, const [
      Po0TokenEntry(token: 'pgnfw_abcdef', name: 'home'),
    ]);
    expect(find.text('home'), findsOneWidget);
  });

  testWidgets('deletes a token after confirming', (tester) async {
    await pumpView(
      tester,
      props: const Po0FirewallProps(
        tokenEntries: [Po0TokenEntry(token: 'pgnfw_abcdefghijk')],
      ),
    );
    final l10n = currentAppLocalizations;

    await tester.tap(find.byTooltip(l10n.delete));
    await tester.pumpAndSettle();
    await tester.tap(find.text(l10n.confirm));
    await tester.pumpAndSettle();
    expect(setting().tokenEntries, isEmpty);
  });

  testWidgets('shows each result with its whitelist', (tester) async {
    await pumpView(
      tester,
      props: const Po0FirewallProps(
        enable: true,
        tokenEntries: [Po0TokenEntry(token: 'pgnfw_a', name: 'home')],
      ),
      state: Po0FirewallState(
        lastRunAt: DateTime(2026, 1, 1, 12),
        results: const [
          Po0TokenResult(
            label: 'pgnfw_a…',
            name: 'home',
            type: Po0ResultType.applied,
            currentIp: '1.2.3.0/24',
            limit: 5,
            whitelist: [
              Po0WhitelistEntry(ip: '1.2.3.0/24'),
              Po0WhitelistEntry(ip: '5.6.7.0/24', slot: 0),
            ],
          ),
          Po0TokenResult(
            label: 'pgnfw_b…',
            type: Po0ResultType.error,
            message: 'timeout',
          ),
        ],
      ),
    );
    final l10n = currentAppLocalizations;

    expect(find.text(l10n.po0StatusApplied), findsOneWidget);
    expect(find.text(l10n.po0StatusError), findsOneWidget);
    expect(find.text('1.2.3.0/24'), findsOneWidget);
    expect(find.text('5.6.7.0/24 #0'), findsOneWidget);
    expect(find.text('timeout'), findsOneWidget);
    expect(find.text(l10n.po0CurrentExit('1.2.3.0/24')), findsOneWidget);

    await tester.tap(find.byTooltip(l10n.po0Query));
    await tester.tap(find.byTooltip(l10n.po0WhitelistNow));
    await tester.pumpAndSettle();
  });
}
