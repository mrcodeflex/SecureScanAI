import 'package:flutter_test/flutter_test.dart';
import 'package:securescan_ai/core/format.dart';
import 'package:securescan_ai/core/models.dart';

void main() {
  test('Scan.fromJson parses website scan with findings', () {
    final scan = Scan.fromJson({
      'id': 'a1b2c3d4',
      'report_id': 'SSAI-20261120-A1B2C3D4',
      'scan_type': 'website',
      'mode': 'beginner',
      'target': 'https://example.test/path',
      'status': 'completed',
      'progress': 100,
      'progress_message': 'Completed',
      'created_at': '2026-11-20T10:00:00Z',
      'score': 72,
      'risk_level': 'medium',
      'summary': {'total': 2, 'high': 1, 'low': 1},
      'engines': [
        {
          'name': 'Built-in',
          'status': 'completed',
          'detail': 'ok',
          'findings': 2,
        },
      ],
      'notes': ['note'],
      'findings': [
        {
          'title': 'Missing header',
          'severity': 'medium',
          'category': 'Security headers',
          'finding_type': 'missing_control',
          'url': 'https://example.test/',
          'cvss_score': 5,
          'references': ['https://owasp.org'],
        },
      ],
    });
    expect(scan.title, 'example.test');
    expect(scan.isCompleted, isTrue);
    expect(scan.totalFindings, 2);
    expect(scan.findings.single.severity, 'medium');
    expect(scan.findings.single.cvssScore, 5.0);
    expect(scan.findings.single.location, 'https://example.test/');
    expect(scan.engines.single.name, 'Built-in');
  });

  test(
    'Source scan title is the file name and file locations include the line',
    () {
      final scan = Scan.fromJson({
        'id': 'x',
        'scan_type': 'source',
        'target': 'code.zip',
        'status': 'running',
      });
      expect(scan.title, 'code.zip');
      expect(scan.isRunning, isTrue);
      final f = Finding.fromJson({
        'title': 't',
        'file_path': 'app/main.py',
        'line': 4,
      });
      expect(f.location, 'app/main.py:4');
    },
  );

  test('Dashboard.fromJson tolerates missing values', () {
    final d = Dashboard.fromJson({
      'totals': {
        'scans': 3,
        'completed': 2,
        'failed': 1,
        'running': 0,
        'average_score': null,
      },
      'severity': {'high': 2},
      'categories': [
        {'name': 'Cookies', 'count': 4},
      ],
      'recent_scans': [],
      'scope': 'own',
    });
    expect(d.totalScans, 3);
    expect(d.severity['high'], 2);
    expect(d.severity['low'], 0);
    expect(d.averageScore, isNull);
    expect(d.categories.single.count, 4);
  });

  test('AppUser role helpers', () {
    final u = AppUser.fromJson({
      'id': 1,
      'username': 'ro',
      'role': 'read_only',
      'role_label': 'Read-only User',
    });
    expect(u.canScan, isFalse);
    expect(u.isAdmin, isFalse);
    expect(
      AppUser.fromJson({'id': 2, 'username': 'a', 'role': 'admin'}).isAdmin,
      isTrue,
    );
  });

  test('format helpers', () {
    expect(formatBytes(2 * 1024 * 1024), '2.0 MB');
    expect(formatBytes(10), '1 KB');
    expect(
      timeAgo(DateTime.now().subtract(const Duration(minutes: 5))),
      '5 min ago',
    );
    expect(timeAgo(null), '-');
    expect(
      formatDuration(
        DateTime.utc(2026, 1, 1, 0, 0, 0),
        DateTime.utc(2026, 1, 1, 0, 2, 5),
      ),
      '2 min 5 s',
    );
  });
}
