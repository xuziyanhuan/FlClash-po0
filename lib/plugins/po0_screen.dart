import 'dart:async';

import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/enum/enum.dart';
import 'package:flutter/services.dart';

class Po0Screen {
  final _channel = const MethodChannel('$packageName/po0_screen');

  void listen(void Function(bool screenOn) onChanged) {
    _channel.setMethodCallHandler((call) async {
      if (call.method == 'screenChanged' && call.arguments is bool) {
        onChanged(call.arguments as bool);
      }
    });
    unawaited(_readInitial(onChanged));
  }

  Future<void> _readInitial(void Function(bool screenOn) onChanged) async {
    try {
      onChanged(await _channel.invokeMethod<bool>('isScreenOn') ?? true);
    } catch (error) {
      commonPrint.log(
        'po0 firewall: reading the screen state failed: $error',
        logLevel: LogLevel.warning,
      );
    }
  }
}

final po0Screen = system.isAndroid ? Po0Screen() : null;
