/// Plain data classes parsed from the SecureScan AI backend JSON.
const List<String> severityOrder = [
  'critical',
  'high',
  'medium',
  'low',
  'info',
];

const Map<String, String> severityLabels = {
  'critical': 'Critical',
  'high': 'High',
  'medium': 'Medium',
  'low': 'Low',
  'info': 'Info',
};

const Map<String, String> findingTypeLabels = {
  'vulnerability': 'Verified vulnerability',
  'misconfiguration': 'Misconfiguration',
  'missing_control': 'Missing control',
  'potential': 'Needs review',
  'observation': 'Observation',
};

String _s(Object? v, [String fallback = '']) =>
    v == null ? fallback : v.toString();
int? _i(Object? v) => v is num ? v.toInt() : int.tryParse(_s(v));

class AppUser {
  AppUser({
    required this.id,
    required this.username,
    required this.fullName,
    required this.role,
    required this.roleLabel,
    required this.mustChangePassword,
    required this.email,
  });

  factory AppUser.fromJson(Map<String, dynamic> j) => AppUser(
    id: _i(j['id']) ?? 0,
    username: _s(j['username']),
    fullName: _s(j['full_name']),
    role: _s(j['role']),
    roleLabel: _s(j['role_label'], _s(j['role'])),
    mustChangePassword: j['must_change_password'] == true,
    email: _s(j['email']),
  );

  final int id;
  final String username;
  final String fullName;
  final String role;
  final String roleLabel;
  final bool mustChangePassword;
  final String email;

  String get displayName => fullName.isNotEmpty ? fullName : username;
  bool get canScan => role != 'read_only';
  bool get isAdmin => role == 'admin' || role == 'super_admin';
}

class Finding {
  Finding({
    required this.title,
    required this.severity,
    required this.category,
    required this.findingType,
    required this.confidence,
    required this.engine,
    required this.ruleId,
    required this.description,
    required this.simpleExplanation,
    required this.whyItMatters,
    required this.remediation,
    required this.evidence,
    this.url,
    this.httpStatus,
    this.filePath,
    this.line,
    this.cwe,
    this.cvssScore,
    this.cvssVector,
    this.references = const [],
  });

  factory Finding.fromJson(Map<String, dynamic> j) => Finding(
    title: _s(j['title']),
    severity: _s(j['severity'], 'info'),
    category: _s(j['category']),
    findingType: _s(j['finding_type']),
    confidence: _s(j['confidence']),
    engine: _s(j['engine']),
    ruleId: _s(j['rule_id']),
    description: _s(j['description']),
    simpleExplanation: _s(j['simple_explanation']),
    whyItMatters: _s(j['why_it_matters']),
    remediation: _s(j['remediation']),
    evidence: _s(j['evidence']),
    url: j['url'] as String?,
    httpStatus: _i(j['http_status']),
    filePath: j['file_path'] as String?,
    line: _i(j['line']),
    cwe: j['cwe'] as String?,
    cvssScore: j['cvss_score'] is num
        ? (j['cvss_score'] as num).toDouble()
        : null,
    cvssVector: j['cvss_vector'] as String?,
    references: (j['references'] is List)
        ? (j['references'] as List).map((e) => e.toString()).toList()
        : const [],
  );

  final String title;
  final String severity;
  final String category;
  final String findingType;
  final String confidence;
  final String engine;
  final String ruleId;
  final String description;
  final String simpleExplanation;
  final String whyItMatters;
  final String remediation;
  final String evidence;
  final String? url;
  final int? httpStatus;
  final String? filePath;
  final int? line;
  final String? cwe;
  final double? cvssScore;
  final String? cvssVector;
  final List<String> references;

  String get location {
    if (url != null && url!.isNotEmpty) return url!;
    if (filePath != null && filePath!.isNotEmpty) {
      return line != null ? '$filePath:$line' : filePath!;
    }
    return '';
  }
}

class EngineRun {
  EngineRun({
    required this.name,
    required this.status,
    required this.detail,
    required this.findings,
  });

  factory EngineRun.fromJson(Map<String, dynamic> j) => EngineRun(
    name: _s(j['name']),
    status: _s(j['status']),
    detail: _s(j['detail']),
    findings: _i(j['findings']) ?? 0,
  );

  final String name;
  final String status;
  final String detail;
  final int findings;
}

class Scan {
  Scan({
    required this.id,
    required this.reportId,
    required this.scanType,
    required this.mode,
    required this.target,
    required this.status,
    required this.progress,
    required this.progressMessage,
    required this.createdAt,
    this.startedAt,
    this.finishedAt,
    required this.owner,
    this.score,
    this.riskLevel,
    required this.summary,
    required this.engines,
    required this.notes,
    this.error,
    required this.activeChecks,
    this.findings = const [],
  });

  factory Scan.fromJson(Map<String, dynamic> j) {
    final summary = <String, int>{};
    final rawSummary = j['summary'];
    if (rawSummary is Map) {
      rawSummary.forEach((k, v) => summary[k.toString()] = _i(v) ?? 0);
    }
    return Scan(
      id: _s(j['id']),
      reportId: _s(j['report_id']),
      scanType: _s(j['scan_type']),
      mode: _s(j['mode']),
      target: _s(j['target']),
      status: _s(j['status']),
      progress: _i(j['progress']) ?? 0,
      progressMessage: _s(j['progress_message']),
      createdAt: DateTime.tryParse(_s(j['created_at'])),
      startedAt: DateTime.tryParse(_s(j['started_at'])),
      finishedAt: DateTime.tryParse(_s(j['finished_at'])),
      owner: _s(j['owner']),
      score: _i(j['score']),
      riskLevel: j['risk_level'] as String?,
      summary: summary,
      engines: (j['engines'] is List)
          ? (j['engines'] as List)
                .whereType<Map<String, dynamic>>()
                .map(EngineRun.fromJson)
                .toList()
          : const [],
      notes: (j['notes'] is List)
          ? (j['notes'] as List).map((e) => e.toString()).toList()
          : const [],
      error: j['error'] as String?,
      activeChecks: j['active_checks'] == true,
      findings: (j['findings'] is List)
          ? (j['findings'] as List)
                .whereType<Map<String, dynamic>>()
                .map(Finding.fromJson)
                .toList()
          : const [],
    );
  }

  final String id;
  final String reportId;
  final String scanType;
  final String mode;
  final String target;
  final String status;
  final int progress;
  final String progressMessage;
  final DateTime? createdAt;
  final DateTime? startedAt;
  final DateTime? finishedAt;
  final String owner;
  final int? score;
  final String? riskLevel;
  final Map<String, int> summary;
  final List<EngineRun> engines;
  final List<String> notes;
  final String? error;
  final bool activeChecks;
  final List<Finding> findings;

  bool get isRunning => status == 'queued' || status == 'running';
  bool get isCompleted => status == 'completed';
  bool get isWebsite => scanType == 'website';
  int get totalFindings => summary['total'] ?? 0;

  String get title {
    if (!isWebsite) return target;
    final uri = Uri.tryParse(target);
    return (uri != null && uri.host.isNotEmpty) ? uri.host : target;
  }
}

class CategoryCount {
  CategoryCount(this.name, this.count);
  final String name;
  final int count;
}

class Dashboard {
  Dashboard({
    required this.totalScans,
    required this.completed,
    required this.failed,
    required this.running,
    this.averageScore,
    required this.severity,
    required this.categories,
    required this.recent,
    required this.scope,
  });

  factory Dashboard.fromJson(Map<String, dynamic> j) {
    final totals =
        (j['totals'] as Map?)?.cast<String, dynamic>() ??
        const <String, dynamic>{};
    final sev = <String, int>{for (final k in severityOrder) k: 0};
    (j['severity'] as Map?)?.forEach((k, v) => sev[k.toString()] = _i(v) ?? 0);
    return Dashboard(
      totalScans: _i(totals['scans']) ?? 0,
      completed: _i(totals['completed']) ?? 0,
      failed: _i(totals['failed']) ?? 0,
      running: _i(totals['running']) ?? 0,
      averageScore: _i(totals['average_score']),
      severity: sev,
      categories: (j['categories'] is List)
          ? (j['categories'] as List)
                .whereType<Map<String, dynamic>>()
                .map((m) => CategoryCount(_s(m['name']), _i(m['count']) ?? 0))
                .toList()
          : const [],
      recent: (j['recent_scans'] is List)
          ? (j['recent_scans'] as List)
                .whereType<Map<String, dynamic>>()
                .map(Scan.fromJson)
                .toList()
          : const [],
      scope: _s(j['scope']),
    );
  }

  final int totalScans;
  final int completed;
  final int failed;
  final int running;
  final int? averageScore;
  final Map<String, int> severity;
  final List<CategoryCount> categories;
  final List<Scan> recent;
  final String scope;
}

class CheckOption {
  CheckOption(this.id, this.label, this.description, this.kind);
  final String id;
  final String label;
  final String description;
  final String kind;
}

class EngineInfo {
  EngineInfo(this.id, this.name, this.state, this.detail);
  final String id;
  final String name;
  final String state;
  final String detail;
}
