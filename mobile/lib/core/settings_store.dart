import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// Persists the backend address (preferences) and the session token (Android Keystore).
class SettingsStore {
  static const String _kServer = 'server_url';
  static const String _kToken = 'session_token';

  final FlutterSecureStorage _secure = const FlutterSecureStorage();

  Future<String?> readServer() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getString(_kServer);
  }

  Future<void> writeServer(String url) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_kServer, url);
  }

  Future<String?> readToken() async {
    try {
      return await _secure.read(key: _kToken);
    } catch (_) {
      return null; // keystore problems must never crash the app; the user simply signs in again
    }
  }

  Future<void> writeToken(String? token) async {
    try {
      if (token == null) {
        await _secure.delete(key: _kToken);
      } else {
        await _secure.write(key: _kToken, value: token);
      }
    } catch (_) {
      // ignore: the session just will not survive an app restart
    }
  }
}
