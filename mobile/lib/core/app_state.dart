import 'package:flutter/material.dart';

import 'api_client.dart';
import 'app_info.dart';
import 'models.dart';
import 'settings_store.dart';
import 'url_rules.dart';

enum BootPhase { loading, ready, offline }

/// Holds the server address, session and the API client for the whole app.
class AppState extends ChangeNotifier {
  AppState({SettingsStore? store}) : _store = store ?? SettingsStore();

  final SettingsStore _store;
  final GlobalKey<NavigatorState> navigatorKey = GlobalKey<NavigatorState>();

  BootPhase phase = BootPhase.loading;
  String? bootError;
  String? serverUrl;
  String? token;
  AppUser? user;
  String? notice;
  ApiClient? _api;

  ApiClient get api => _api!;
  bool get hasServer => serverUrl != null;
  bool get signedIn => token != null && user != null;

  void _buildApi() {
    _api?.close();
    _api = serverUrl == null
        ? null
        : ApiClient(
            baseUrl: serverUrl!,
            token: token,
            onUnauthorized: _sessionExpired,
          );
  }

  Future<void> init() async {
    phase = BootPhase.loading;
    bootError = null;
    notifyListeners();
    final minimumSplash = Future<void>.delayed(
      const Duration(milliseconds: 1100),
    );
    var stored = await _store.readServer();
    if ((stored == null || stored.isEmpty) && kDefaultServer.isNotEmpty) {
      final check = normalizeServerUrl(kDefaultServer);
      if (check.isValid) stored = check.url;
    }
    serverUrl = (stored == null || stored.isEmpty) ? null : stored;
    token = await _store.readToken();
    _buildApi();
    if (serverUrl != null && token != null) {
      try {
        user = await api.me();
      } on ApiException catch (e) {
        if (e.isUnauthorized) {
          token = null;
          await _store.writeToken(null);
          _buildApi();
        } else {
          bootError = e.message;
          await minimumSplash;
          phase = BootPhase.offline;
          notifyListeners();
          return;
        }
      }
    }
    await minimumSplash;
    phase = BootPhase.ready;
    notifyListeners();
  }

  Future<void> setServer(String url) async {
    final changed = url != serverUrl;
    serverUrl = url;
    await _store.writeServer(url);
    if (changed) {
      token = null;
      user = null;
      await _store.writeToken(null);
    }
    _buildApi();
    notifyListeners();
  }

  Future<void> login(String username, String password) async {
    final probe = ApiClient(baseUrl: serverUrl!);
    try {
      final result = await probe.login(username, password);
      token = result.token;
      user = result.user;
      notice = null;
      await _store.writeToken(token);
      _buildApi();
      notifyListeners();
    } finally {
      probe.close();
    }
  }

  void updateUser(AppUser updated) {
    user = updated;
    notifyListeners();
  }

  Future<void> logout() async {
    try {
      await _api?.logout();
    } finally {
      await _clearSession();
    }
  }

  Future<void> _clearSession() async {
    token = null;
    user = null;
    await _store.writeToken(null);
    _buildApi();
    navigatorKey.currentState?.popUntil((route) => route.isFirst);
    notifyListeners();
  }

  void _sessionExpired() {
    if (token == null) return;
    notice = 'Your session expired. Please sign in again.';
    _clearSession();
  }
}

/// Makes [AppState] available to the widget tree.
class AppScope extends InheritedNotifier<AppState> {
  const AppScope({super.key, required AppState state, required super.child})
    : super(notifier: state);

  static AppState of(BuildContext context) {
    final scope = context.dependOnInheritedWidgetOfExactType<AppScope>();
    assert(scope != null, 'AppScope not found');
    return scope!.notifier!;
  }
}
