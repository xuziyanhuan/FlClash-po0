import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/models/models.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:yaml/yaml.dart';

typedef _Call = ({String method, Uri uri});

class _FakeApi {
  final List<Object> responses;
  final calls = <_Call>[];

  _FakeApi(this.responses);

  Future<Po0HttpResponse> send(String method, Uri uri) async {
    calls.add((method: method, uri: uri));
    final next = responses.length > 1 ? responses.removeAt(0) : responses[0];
    if (next is Po0HttpResponse) {
      return next;
    }
    throw next as Exception;
  }
}

Po0HttpResponse _ok({
  String currentIp = '45.82.120.0/24',
  List<Object> whitelist = const [
    {'ip': '45.82.120.0/24', 'slot': null},
    {'ip': '1.2.3.0/24', 'slot': 0},
  ],
  bool enabled = true,
}) {
  final items = whitelist.map(
    (item) => item is Map
        ? '{"ip":"${item['ip']}","slot":${item['slot']}}'
        : '"$item"',
  );
  return Po0HttpResponse(
    200,
    '{"enabled":$enabled,"whitelist":[${items.join(',')}],'
    '"limit":5,"currentIp":"$currentIp"}',
  );
}

Po0FirewallClient _client(_FakeApi api) =>
    Po0FirewallClient(send: api.send, retryDelay: Duration.zero);

const _token = Po0Token('pgnfw_secret_token_value');

const Po0DirectEndpoint _endpoint = (port: 40123, username: 'u', password: 'p');

const _listener = {
  'name': 'po0-direct',
  'type': 'http',
  'listen': '127.0.0.1',
  'port': 40123,
  'users': [
    {'username': 'u', 'password': 'p'},
  ],
  'proxy': 'DIRECT',
};

void main() {
  group('tokens', () {
    test('a token is one pgnfw_ value without separators', () {
      expect(isPo0Token('pgnfw_abc'), isTrue);
      expect(isPo0Token('pgnfw_'), isFalse);
      expect(isPo0Token('pgnfw_a,pgnfw_b'), isFalse);
      expect(isPo0Token('pgnfw_a@1'), isFalse);
      expect(isPo0Token('abc'), isFalse);
    });

    test('skips invalid and repeated tokens, keeping the first', () {
      final tokens = po0TokensOf(const [
        Po0TokenEntry(token: 'pgnfw_a', name: 'home'),
        Po0TokenEntry(token: 'nope'),
        Po0TokenEntry(token: 'pgnfw_a', name: 'again'),
        Po0TokenEntry(token: 'pgnfw_b'),
      ]);
      expect(tokens.map((it) => it.token.value), ['pgnfw_a', 'pgnfw_b']);
      expect(tokens.first.name, 'home');
    });

    test('labels never expose the whole token', () {
      expect(_token.label, 'pgnfw_secret…');
      expect(_token, const Po0Token('pgnfw_secret_token_value'));
      expect(_token.hashCode, _token.value.hashCode);
    });
  });

  group('direct listener', () {
    test('is added once, replacing a stale copy and keeping others', () {
      final config = withPo0DirectListener({
        'listeners': [
          {'name': 'po0-direct', 'port': 1},
          {'name': 'other'},
        ],
      }, _endpoint);
      expect(config['listeners'], [
        {'name': 'other'},
        _listener,
      ]);
    });

    test('requests reach it with its own credentials', () {
      expect(po0FindProxy(_endpoint), 'PROXY u:p@127.0.0.1:40123; DIRECT');
      expect(po0FindProxy(null), 'DIRECT');
    });

    test('opens one free loopback port for the whole session', () async {
      final listener = Po0DirectListener();
      final first = await listener.endpoint;
      expect(await listener.endpoint, same(first));
      expect(first.port, greaterThan(0));
      expect(first.username, hasLength(12));
      expect(first.password, hasLength(24));
    });
  });

  test('sameC24 matches exact addresses and /24 networks either way', () {
    expect(sameC24('1.2.3.4', '1.2.3.4'), isTrue);
    expect(sameC24('1.2.3.0/24', '1.2.3.9'), isTrue);
    expect(sameC24('1.2.3.9', '1.2.3.0/24'), isTrue);
    expect(sameC24('1.2.3.4', '1.2.3.5'), isFalse);
    expect(sameC24('1.2.4.0/24', '1.2.3.9'), isFalse);
    expect(sameC24(null, '1.2.3.4'), isFalse);
    expect(sameC24('', '1.2.3.4'), isFalse);
  });

  group('Po0FirewallClient', () {
    test('whitelists through the add endpoint', () async {
      final api = _FakeApi([_ok()]);
      final result = await _client(api).whitelist(const Po0Token('pgnfw_a'));

      expect(api.calls.single.method, 'POST');
      expect(
        api.calls.single.uri.toString(),
        'https://124.221.69.228/api/firewall/pgnfw_a/add',
      );
      expect(result.type, Po0ResultType.applied);
      expect(result.currentIp, '45.82.120.0/24');
      expect(result.limit, 5);
      expect(result.whitelist, [
        const Po0WhitelistEntry(ip: '45.82.120.0/24'),
        const Po0WhitelistEntry(ip: '1.2.3.0/24', slot: 0),
      ]);
    });

    test('queries read-only without touching the add endpoint', () async {
      final api = _FakeApi([
        _ok(currentIp: '9.9.9.9', whitelist: ['1.2.3.4']),
      ]);
      final result = await _client(api).query(_token);

      expect(api.calls.single.method, 'GET');
      expect(api.calls.single.uri.path, '/api/firewall/${_token.value}');
      expect(result.type, Po0ResultType.notApplied);
      expect(result.whitelist.single.ip, '1.2.3.4');
    });

    test('reports a disabled firewall', () async {
      final result = await _client(
        _FakeApi([_ok(enabled: false)]),
      ).whitelist(_token);
      expect(result.type, Po0ResultType.disabled);
    });

    test('a 403 is final and reports its message', () async {
      final api = _FakeApi([
        const Po0HttpResponse(403, '{"currentIp":"1.1.1.1","message":"no"}'),
      ]);
      final result = await _client(api).whitelist(_token);
      expect(result.type, Po0ResultType.rejected);
      expect(result.message, 'no');
      expect(result.currentIp, '1.1.1.1');
      expect(api.calls, hasLength(1));
    });

    test('a JSON error body is final', () async {
      final api = _FakeApi([
        const Po0HttpResponse(400, '{"code":400,"message":"invalid token"}'),
      ]);
      final result = await _client(api).whitelist(_token);
      expect(result.type, Po0ResultType.rejected);
      expect(result.message, 'invalid token');
      expect(api.calls, hasLength(1));
    });

    test('retries transient failures before succeeding', () async {
      final api = _FakeApi([
        const SocketException('reset'),
        const Po0HttpResponse(400, 'Error'),
        const Po0HttpResponse(503, 'busy'),
        _ok(),
      ]);
      final client = Po0FirewallClient(
        send: api.send,
        retryDelay: Duration.zero,
        maxAttempts: 4,
      );
      final result = await client.whitelist(_token);
      expect(result.type, Po0ResultType.applied);
      expect(api.calls, hasLength(4));
    });

    test('gives up after the last attempt and redacts the token', () async {
      final api = _FakeApi([
        HttpException(
          'Connection closed',
          uri: Uri.parse('https://x/api/firewall/${_token.value}/add'),
        ),
      ]);
      final result = await _client(api).whitelist(_token);
      expect(result.type, Po0ResultType.error);
      expect(api.calls, hasLength(3));
      expect(result.message, contains(_token.label));
      expect(result.message, isNot(contains(_token.value)));
    });

    test('a poll reads once and leaves retrying to the next poll', () async {
      final api = _FakeApi([const Po0HttpResponse(400, 'Error'), _ok()]);
      final result = await _client(api).poll(_token);
      expect(api.calls.single.method, 'GET');
      expect(result.type, Po0ResultType.error);
    });

    test('a timed-out request drops the pooled connection', () async {
      var resets = 0;
      final client = Po0FirewallClient(
        send: (_, _) => Completer<Po0HttpResponse>().future,
        resetConnections: () => resets++,
        pollTimeout: const Duration(milliseconds: 10),
      );
      final result = await client.poll(_token);
      expect(result.type, Po0ResultType.error);
      expect(resets, 1);
    });

    test('an exit already pinned on the server counts as listed', () async {
      final result = await _client(
        _FakeApi([
          _ok(
            currentIp: '1.2.3.0/24',
            whitelist: const [
              {'ip': '1.2.3.0/24', 'slot': 0},
            ],
          ),
        ]),
      ).poll(const Po0Token('pgnfw_a'));
      expect(result.type, Po0ResultType.applied);
    });

    test('a 2xx body without a whitelist is an error', () async {
      final result = await _client(
        _FakeApi([const Po0HttpResponse(200, '{"ok":true}')]),
      ).whitelist(_token);
      expect(result.type, Po0ResultType.error);
    });

    test('a non-JSON final body never shows the token', () async {
      final result = await _client(
        _FakeApi([Po0HttpResponse(403, 'denied ${_token.value}')]),
      ).whitelist(_token);
      expect(result.type, Po0ResultType.error);
      expect(result.message, isNot(contains(_token.value)));
    });

    test('resetting without a pooled connection is harmless', () {
      expect(Po0FirewallClient().resetConnections, returnsNormally);
    });
  });

  test('the po0 security context loads the bundled root', () {
    expect(() => po0SecurityContext, returnsNormally);
  });

  group('makeRealProfileTask', () {
    TestWidgetsFlutterBinding.ensureInitialized();

    Future<YamlMap> build(
      List<String> directCidrs, {
      bool listener = false,
    }) async {
      final rawConfig = <String, dynamic>{
        'tun': <String, dynamic>{
          'route-exclude-address': <dynamic>['192.168.0.0/16'],
        },
        'rules': <dynamic>['MATCH,Proxy'],
      };
      final result = await makeRealProfileTask(
        MakeRealProfileState(
          profilesPath: Directory.systemTemp.path,
          profileId: 1,
          rawConfig: listener
              ? withPo0DirectListener(rawConfig, _endpoint)
              : rawConfig,
          realPatchConfig: const PatchClashConfig(),
          appendSystemDns: false,
          proxyGroups: const [],
          rules: const [],
          addedRules: const [],
          defaultUA: 'FlClash-Test',
          directCidrs: directCidrs,
        ),
      );
      return loadYaml(result.yaml) as YamlMap;
    }

    test('routes the API DIRECT and keeps it out of TUN', () async {
      final config = await build(const [po0FirewallDirectCidr]);
      expect(config['rules'], [
        'IP-CIDR,124.221.69.228/32,DIRECT,no-resolve',
        'MATCH,Proxy',
      ]);
      expect(
        config['tun']['route-exclude-address'],
        containsAll(['192.168.0.0/16', '124.221.69.228/32']),
      );
    });

    test('keeps the direct listener in the written profile', () async {
      final config = await build(const [], listener: true);
      expect(config['listeners'], [_listener]);
    });

    test('leaves the profile alone while disabled', () async {
      final config = await build(const []);
      expect(config['rules'], ['MATCH,Proxy']);
      expect(
        config['tun']['route-exclude-address'],
        isNot(contains('124.221.69.228/32')),
      );
    });
  });

  group('Po0FirewallProps', () {
    test('round-trips through JSON', () {
      const props = Po0FirewallProps(
        enable: true,
        tokenEntries: [Po0TokenEntry(token: 'pgnfw_a', name: 'home')],
        pollSeconds: 9,
      );
      final json = jsonDecode(jsonEncode(props)) as Map<String, Object?>;
      expect(Po0FirewallProps.safeFromJson(json), props);
    });

    test('restores the defaults from damaged or missing settings', () {
      expect(Po0FirewallProps.safeFromJson(null), defaultPo0FirewallProps);
      expect(
        Po0FirewallProps.safeFromJson({'enable': 'yes'}),
        defaultPo0FirewallProps,
      );
    });

    test('a config without the section keeps the default', () {
      final json =
          jsonDecode(jsonEncode(Config(themeProps: defaultThemeProps)))
              as Map<String, Object?>;
      final config = Config.fromJson(json..remove('po0FirewallProps'));
      expect(config.po0FirewallProps, defaultPo0FirewallProps);
    });
  });
}
