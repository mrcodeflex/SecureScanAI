/// Validation of the backend address entered on the phone.
///
/// Rules (see SECURITY.md):
///  * localhost / 127.x / 0.0.0.0 refer to the phone itself and are rejected.
///  * https:// is accepted for any host. TLS certificates are always verified.
///  * http:// is accepted only for hosts on a trusted local network
///    (RFC 1918 addresses, link-local, *.local / *.lan names, single-label names).
class UrlCheck {
  const UrlCheck.ok(String this.url) : error = null;
  const UrlCheck.error(String this.error) : url = null;

  final String? url;
  final String? error;

  bool get isValid => url != null;
}

final RegExp _ipv4 = RegExp(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$');

bool isLoopbackHost(String host) {
  final h = host.toLowerCase();
  if (h == 'localhost' ||
      h.endsWith('.localhost') ||
      h == '::1' ||
      h == '0.0.0.0') {
    return true;
  }
  final m = _ipv4.firstMatch(h);
  return m != null && int.parse(m.group(1)!) == 127;
}

/// True for hosts that are on a private / local network.
bool isPrivateHost(String host) {
  final h = host.toLowerCase();
  final m = _ipv4.firstMatch(h);
  if (m != null) {
    final a = int.parse(m.group(1)!);
    final b = int.parse(m.group(2)!);
    if (a == 10) return true;
    if (a == 172 && b >= 16 && b <= 31) return true;
    if (a == 192 && b == 168) return true;
    if (a == 169 && b == 254) return true;
    return false;
  }
  if (h.contains(':')) {
    return h.startsWith('fc') || h.startsWith('fd') || h.startsWith('fe80');
  }
  if (!h.contains('.')) return true; // single-label name such as "mypc"
  return h.endsWith('.local') ||
      h.endsWith('.lan') ||
      h.endsWith('.home') ||
      h.endsWith('.internal');
}

UrlCheck normalizeServerUrl(String input) {
  var text = input.trim();
  if (text.isEmpty) {
    return const UrlCheck.error(
      'Enter the server address, for example http://192.168.1.20:8000',
    );
  }
  if (text.contains(RegExp(r'\s'))) {
    return const UrlCheck.error('The address must not contain spaces.');
  }
  final hasScheme = RegExp(r'^[a-zA-Z][a-zA-Z0-9+.\-]*://').hasMatch(text);
  if (!hasScheme) text = 'placeholder://$text';
  Uri uri;
  try {
    uri = Uri.parse(text);
  } on FormatException {
    return const UrlCheck.error('That does not look like a valid address.');
  }
  final host = uri.host;
  if (host.isEmpty) {
    return const UrlCheck.error('That does not look like a valid address.');
  }
  if (uri.userInfo.isNotEmpty) {
    return const UrlCheck.error(
      'Do not put a user name or password in the address.',
    );
  }
  if (isLoopbackHost(host)) {
    return const UrlCheck.error(
      'localhost refers to this phone, not your computer. Use the computer\'s LAN address (run ipconfig on Windows), for example http://192.168.1.20:8000',
    );
  }
  final scheme = hasScheme
      ? uri.scheme.toLowerCase()
      : (isPrivateHost(host) ? 'http' : 'https');
  if (scheme != 'http' && scheme != 'https') {
    return const UrlCheck.error('Use an http:// or https:// address.');
  }
  if (scheme == 'http' && !isPrivateHost(host)) {
    return const UrlCheck.error(
      'Plain HTTP is only allowed on a trusted local network. Use an https:// address for this server.',
    );
  }
  final defaultPort = scheme == 'https' ? 443 : 80;
  final port = uri.hasPort && uri.port != defaultPort ? ':${uri.port}' : '';
  var path = uri.path;
  while (path.endsWith('/')) {
    path = path.substring(0, path.length - 1);
  }
  final hostPart = host.contains(':') ? '[$host]' : host.toLowerCase();
  return UrlCheck.ok('$scheme://$hostPart$port$path');
}
