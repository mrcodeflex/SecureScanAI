import 'package:flutter_test/flutter_test.dart';
import 'package:securescan_ai/core/url_rules.dart';

void main() {
  group('normalizeServerUrl accepts', () {
    final accepted = <String, String>{
      '192.168.1.20:8000': 'http://192.168.1.20:8000',
      'http://192.168.1.20:8000/': 'http://192.168.1.20:8000',
      '10.0.0.5:8000': 'http://10.0.0.5:8000',
      'http://MYPC:8000': 'http://mypc:8000',
      'http://nas.local:8000': 'http://nas.local:8000',
      'https://scan.example.com': 'https://scan.example.com',
      'scan.example.com/': 'https://scan.example.com',
      'https://scan.example.com:8443/app/': 'https://scan.example.com:8443/app',
    };
    accepted.forEach((input, expected) {
      test(input, () {
        final r = normalizeServerUrl(input);
        expect(r.isValid, isTrue, reason: r.error);
        expect(r.url, expected);
      });
    });
  });

  group('normalizeServerUrl rejects', () {
    for (final bad in [
      '',
      'localhost:8000',
      'http://127.0.0.1:8000',
      'http://0.0.0.0',
      'http://[::1]:8000',
      'http://example.com',
      'http://8.8.8.8:8000',
      'ftp://192.168.1.2',
      'http://user:pass@192.168.1.2',
      'http://a b',
    ]) {
      test('"$bad"', () {
        final r = normalizeServerUrl(bad);
        expect(r.isValid, isFalse);
        expect(r.error, isNotEmpty);
      });
    }
  });

  test('private host detection', () {
    expect(isPrivateHost('172.16.0.1'), isTrue);
    expect(isPrivateHost('172.32.0.1'), isFalse);
    expect(isPrivateHost('192.168.0.9'), isTrue);
    expect(isPrivateHost('8.8.8.8'), isFalse);
    expect(isPrivateHost('printer'), isTrue);
    expect(isPrivateHost('example.com'), isFalse);
  });
}
