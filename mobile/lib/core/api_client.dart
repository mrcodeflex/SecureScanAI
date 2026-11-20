import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:file_selector/file_selector.dart';
import 'package:http/http.dart' as http;
import 'package:path_provider/path_provider.dart';

import 'models.dart';

class ApiException implements Exception {
  ApiException(this.message, {this.status});

  final String message;
  final int? status;

  bool get isUnauthorized => status == 401;

  @override
  String toString() => message;
}

/// Thin client for the SecureScan AI REST API. TLS certificates are always verified.
class ApiClient {
  ApiClient({
    required this.baseUrl,
    this.token,
    http.Client? client,
    this.onUnauthorized,
  }) : _client = client ?? http.Client();

  final String baseUrl;
  String? token;
  final http.Client _client;
  final void Function()? onUnauthorized;

  Uri _uri(String path, [Map<String, String>? query]) {
    final uri = Uri.parse('$baseUrl/api$path');
    return query == null || query.isEmpty
        ? uri
        : uri.replace(queryParameters: query);
  }

  Map<String, String> get _headers => {
    'Accept': 'application/json',
    if (token != null) 'Authorization': 'Bearer $token',
  };

  Future<T> _guard<T>(Future<T> Function() action) async {
    try {
      return await action();
    } on ApiException {
      rethrow;
    } on TimeoutException {
      throw ApiException(
        'The server did not respond in time. Check the address and your Wi-Fi connection.',
      );
    } on TlsException {
      throw ApiException(
        'The secure connection could not be verified (certificate problem). Certificate validation is never disabled.',
      );
    } on SocketException {
      throw ApiException(
        'Cannot reach the server. Check the address, that the server is running, '
        'and that Windows Firewall allows the port.',
      );
    } on http.ClientException {
      throw ApiException(
        'Cannot reach the server. Check the address and your connection.',
      );
    } on FormatException {
      throw ApiException(
        'The server sent an unexpected response. Is this a SecureScan AI server?',
      );
    }
  }

  dynamic _decode(http.Response res, {bool authEndpoint = false}) {
    dynamic data;
    if (res.bodyBytes.isNotEmpty) {
      try {
        data = jsonDecode(utf8.decode(res.bodyBytes));
      } on FormatException {
        data = null;
      }
    }
    if (res.statusCode == 401 && !authEndpoint) {
      onUnauthorized?.call();
      throw ApiException(
        'Your session has expired. Please sign in again.',
        status: 401,
      );
    }
    if (res.statusCode >= 400) {
      final detail = data is Map ? data['detail'] : null;
      throw ApiException(
        detail is String ? detail : 'Request failed (${res.statusCode}).',
        status: res.statusCode,
      );
    }
    return data;
  }

  Future<dynamic> _get(
    String path, {
    Map<String, String>? query,
    Duration timeout = const Duration(seconds: 20),
  }) => _guard(
    () async => _decode(
      await _client.get(_uri(path, query), headers: _headers).timeout(timeout),
    ),
  );

  Future<dynamic> _post(String path, {Object? body, bool auth = false}) =>
      _guard(() async {
        final res = await _client
            .post(
              _uri(path),
              headers: {..._headers, 'Content-Type': 'application/json'},
              body: body == null ? null : jsonEncode(body),
            )
            .timeout(const Duration(seconds: 20));
        return _decode(res, authEndpoint: auth);
      });

  // ---- public API ----------------------------------------------------------------
  Future<Map<String, dynamic>> health() async {
    final data = await _guard(() async {
      final res = await _client
          .get(_uri('/health'), headers: {'Accept': 'application/json'})
          .timeout(const Duration(seconds: 8));
      return _decode(res, authEndpoint: true);
    });
    if (data is! Map<String, dynamic> || data['status'] != 'ok') {
      throw ApiException(
        'The server answered, but it does not look like SecureScan AI.',
      );
    }
    return data;
  }

  Future<({String token, AppUser user})> login(
    String username,
    String password,
  ) async {
    final data = await _post(
      '/auth/login',
      body: {'username': username, 'password': password},
      auth: true,
    );
    return (
      token: data['token'] as String,
      user: AppUser.fromJson((data['user'] as Map).cast<String, dynamic>()),
    );
  }

  Future<AppUser> me() async => AppUser.fromJson(
    ((await _get('/auth/me')) as Map).cast<String, dynamic>(),
  );

  Future<void> logout() async {
    try {
      await _post('/auth/logout');
    } on ApiException {
      // already signed out on the server
    }
  }

  Future<AppUser> changePassword(String current, String next) async {
    final data = await _post(
      '/auth/change-password',
      body: {'current_password': current, 'new_password': next},
    );
    return AppUser.fromJson(
      ((data as Map)['user'] as Map).cast<String, dynamic>(),
    );
  }

  Future<Dashboard> dashboard() async => Dashboard.fromJson(
    ((await _get('/dashboard')) as Map).cast<String, dynamic>(),
  );

  Future<({int total, List<Scan> items})> listScans({
    String? status,
    String? query,
    int offset = 0,
    int limit = 20,
  }) async {
    final data = (await _get(
      '/scans',
      query: {
        'limit': '$limit',
        'offset': '$offset',
        if (status != null && status.isNotEmpty) 'status': status,
        if (query != null && query.isNotEmpty) 'q': query,
      },
    )) as Map;
    final items = (data['items'] as List)
        .whereType<Map<String, dynamic>>()
        .map(Scan.fromJson)
        .toList();
    return (total: (data['total'] as num).toInt(), items: items);
  }

  Future<Scan> getScan(String id) async => Scan.fromJson(
    ((await _get('/scans/$id')) as Map).cast<String, dynamic>(),
  );

  Future<Scan> startWebsiteScan({
    required String url,
    required String mode,
    List<String>? checks,
    bool activeChecks = false,
  }) async {
    final data = await _post(
      '/scans/website',
      body: {
        'url': url,
        'mode': mode,
        'checks': checks,
        'active_checks': activeChecks,
        'engines': <String>[],
        'authorization_confirmed': true,
      },
    );
    return Scan.fromJson((data as Map).cast<String, dynamic>());
  }

  Future<Scan> startSourceScan({
    required XFile file,
    required String mode,
    List<String> engines = const [],
  }) => _guard(() async {
    final request = http.MultipartRequest('POST', _uri('/scans/source'))
      ..headers.addAll(_headers)
      ..fields['mode'] = mode
      ..fields['authorization_confirmed'] = 'true'
      ..fields['engines'] = engines.join(',')
      ..files.add(
        http.MultipartFile(
          'file',
          file.openRead(),
          await file.length(),
          filename: file.name,
        ),
      );
    final streamed = await _client
        .send(request)
        .timeout(const Duration(minutes: 5));
    final res = await http.Response.fromStream(streamed);
    return Scan.fromJson((_decode(res) as Map).cast<String, dynamic>());
  });

  Future<void> cancelScan(String id) async => _post('/scans/$id/cancel');

  Future<void> deleteScan(String id) => _guard(() async {
    final res = await _client
        .delete(_uri('/scans/$id'), headers: _headers)
        .timeout(const Duration(seconds: 20));
    _decode(res);
  });

  Future<List<CheckOption>> checks() async {
    final data = (await _get('/system/checks')) as List;
    return data
        .whereType<Map<String, dynamic>>()
        .map(
          (m) => CheckOption(
            '${m['id']}',
            '${m['label']}',
            '${m['description']}',
            '${m['kind']}',
          ),
        )
        .toList();
  }

  Future<List<EngineInfo>> engines() async {
    final data = (await _get('/system/engines')) as List;
    return data
        .whereType<Map<String, dynamic>>()
        .map(
          (m) => EngineInfo(
            '${m['id']}',
            '${m['name']}',
            '${m['state']}',
            '${m['detail']}',
          ),
        )
        .toList();
  }

  /// Downloads a report (pdf | json | csv) into the app's documents folder and returns the file.
  Future<File> downloadReport(String scanId, String format, String reportId) =>
      _guard(() async {
        final res = await _client
            .get(
              _uri('/scans/$scanId/report.$format'),
              headers: {..._headers, 'Accept': '*/*'},
            )
            .timeout(const Duration(seconds: 90));
        if (res.statusCode >= 400) _decode(res);
        final dir = await getApplicationDocumentsDirectory();
        final safe = reportId.replaceAll(RegExp(r'[^A-Za-z0-9._-]'), '_');
        final file = File('${dir.path}/SecureScanAI-$safe.$format');
        await file.writeAsBytes(res.bodyBytes, flush: true);
        return file;
      });

  void close() => _client.close();
}
