import 'dart:async';
import 'dart:math';

import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/models/models.dart';
import 'package:flutter/foundation.dart';
import 'package:riverpod_annotation/riverpod_annotation.dart';

import 'config.dart';
import 'state.dart';

part 'generated/po0_firewall.g.dart';

@Riverpod(keepAlive: true)
Po0FirewallClient po0FirewallClient(Ref ref) => Po0FirewallClient(
  endpoint: () async {
    if (!ref.read(isStartProvider) || ref.read(suspendProvider)) {
      return null;
    }
    return po0DirectListener.endpoint;
  },
);

/// Keeps the current exit whitelisted for as long as the app runs, whether or
/// not the proxy is started. Android pauses while the screen is off.
@Riverpod(keepAlive: true)
class Po0Firewall extends _$Po0Firewall {
  static const maxBackoff = Duration(seconds: 30);

  /// Turning the switch on reapplies the profile through `setupPatchProvider`
  /// with its debounce; the first add waits for the DIRECT route to land.
  static const routingDelay = Duration(seconds: 2);

  Timer? _timer;
  bool _started = false;
  bool _screenOn = true;
  bool _inFlight = false;
  Po0RunKind? _queued;
  int _failures = 0;
  int _generation = 0;
  final _signatures = <String, String>{};

  Po0FirewallProps get _setting => ref.read(po0FirewallSettingProvider);

  @override
  Po0FirewallState build() {
    ref.onDispose(_cancelTimer);
    ref.listen(po0FirewallSettingProvider, _handleSettingChanged);
    return const Po0FirewallState();
  }

  static Duration pollIntervalOf(Po0FirewallProps setting) => Duration(
    seconds: setting.pollSeconds.clamp(
      po0PollSecondsRange.min,
      po0PollSecondsRange.max,
    ),
  );

  /// Called once the app has attached: Core runs and the profile already
  /// carries the DIRECT route for the API, so the first request cannot leave
  /// through the proxy.
  void start() {
    if (_started) {
      return;
    }
    _started = true;
    pollNow();
  }

  void pollNow() => unawaited(_run(Po0RunKind.poll));

  void setScreenOn(bool value) {
    if (_screenOn == value) {
      return;
    }
    _screenOn = value;
    if (value) {
      pollNow();
    } else {
      _cancelTimer();
    }
  }

  void onNetworkChanged() {
    if (!_started || !_setting.enable) {
      return;
    }
    ref.read(po0FirewallClientProvider).resetConnections();
    _failures = 0;
    pollNow();
  }

  Future<void> whitelist() => _run(Po0RunKind.whitelist);

  Future<void> query() => _run(Po0RunKind.query);

  @protected
  DateTime now() => DateTime.now();

  void _handleSettingChanged(Po0FirewallProps? prev, Po0FirewallProps next) {
    if (!_started || prev == null || prev == next) {
      return;
    }
    if (prev.enable != next.enable) {
      _generation++;
      _cancelTimer();
      _queued = null;
      _failures = 0;
      if (next.enable) {
        _timer = Timer(routingDelay, () => unawaited(whitelist()));
      } else if (state.isRunning) {
        state = state.copyWith(isRunning: false);
      }
      return;
    }
    if (!listEquals(_tokensIn(prev), _tokensIn(next))) {
      _signatures.clear();
      unawaited(whitelist());
      return;
    }
    if (pollIntervalOf(prev) != pollIntervalOf(next) && !_inFlight) {
      _scheduleNext();
    }
  }

  List<Po0Token> _tokensIn(Po0FirewallProps setting) =>
      po0TokensOf(setting.tokenEntries).map((it) => it.token).toList();

  void _setBusy(bool busy) {
    if (state.isRunning != busy) {
      state = state.copyWith(isRunning: busy);
    }
  }

  Future<void> _run(Po0RunKind kind) async {
    final setting = _setting;
    final entries = po0TokensOf(setting.tokenEntries);
    final tokens = entries.map((it) => it.token).toList();
    if (!_started || !setting.enable || tokens.isEmpty) {
      _cancelTimer();
      return;
    }
    if (kind == Po0RunKind.poll && !_screenOn) {
      return;
    }
    if (_inFlight) {
      final queued = _queued;
      if (queued == null || kind.index > queued.index) {
        _queued = kind;
        if (kind != Po0RunKind.poll) {
          _setBusy(true);
        }
      }
      return;
    }
    _inFlight = true;
    final generation = _generation;
    _cancelTimer();
    if (kind != Po0RunKind.poll) {
      _setBusy(true);
    }
    final client = ref.read(po0FirewallClientProvider);
    final added = <int>{};
    List<Po0TokenResult> results;
    try {
      results = await Future.wait(
        tokens.indexed.map(
          (entry) => switch (kind) {
            Po0RunKind.poll => _pollToken(client, entry.$2, () {
              added.add(entry.$1);
            }),
            Po0RunKind.whitelist => client.whitelist(entry.$2),
            Po0RunKind.query => client.query(entry.$2),
          },
        ),
      );
    } catch (error) {
      results = [
        for (final token in tokens)
          Po0TokenResult(
            label: token.label,
            type: Po0ResultType.error,
            message: '$error',
          ),
      ];
    } finally {
      _inFlight = false;
    }
    if (!ref.mounted || generation != _generation) {
      return;
    }
    results = [
      for (final (index, result) in results.indexed)
        result.copyWith(
          name: entries[index].name.isEmpty ? null : entries[index].name,
        ),
    ];
    _failures = results.any((it) => it.type == Po0ResultType.error)
        ? _failures + 1
        : 0;
    final queued = _queued;
    _queued = null;
    state = Po0FirewallState(
      lastRunAt: now(),
      lastRunKind: kind,
      isRunning: queued != null && queued != Po0RunKind.poll,
      results: results,
    );
    _log(kind, tokens, results, added);
    if (queued != null) {
      unawaited(_run(queued));
    } else {
      _scheduleNext();
    }
  }

  Future<Po0TokenResult> _pollToken(
    Po0FirewallClient client,
    Po0Token token,
    void Function() onAdd,
  ) async {
    final status = await client.poll(token);
    if (status.type != Po0ResultType.notApplied) {
      return status;
    }
    onAdd();
    return client.whitelist(token);
  }

  void _scheduleNext() {
    _cancelTimer();
    final setting = _setting;
    if (!_started ||
        !setting.enable ||
        !_screenOn ||
        po0TokensOf(setting.tokenEntries).isEmpty) {
      return;
    }
    _timer = Timer(nextDelayFor(_failures, pollIntervalOf(setting)), pollNow);
  }

  @visibleForTesting
  static Duration nextDelayFor(int failures, Duration interval) {
    if (failures == 0) {
      return interval;
    }
    final backoff = interval * (1 << min(failures, 4));
    final cap = interval > maxBackoff ? interval : maxBackoff;
    return backoff < cap ? backoff : cap;
  }

  void _log(
    Po0RunKind kind,
    List<Po0Token> tokens,
    List<Po0TokenResult> results,
    Set<int> added,
  ) {
    for (final (index, result) in results.indexed) {
      final signature = '${result.type.name} ${result.currentIp}';
      final changed = _signatures[tokens[index].value] != signature;
      _signatures[tokens[index].value] = signature;
      if (kind == Po0RunKind.poll && !changed && !added.contains(index)) {
        continue;
      }
      final action = kind == Po0RunKind.poll && added.contains(index)
          ? 'whitelist'
          : kind.name;
      final detail = [?result.currentIp, ?result.message].join(' ');
      commonPrint.log(
        'po0 firewall $action #${index + 1} ${result.label} '
        '${result.type.name} $detail',
        logLevel: result.type == Po0ResultType.applied
            ? LogLevel.info
            : LogLevel.warning,
      );
    }
  }

  void _cancelTimer() {
    _timer?.cancel();
    _timer = null;
  }
}
