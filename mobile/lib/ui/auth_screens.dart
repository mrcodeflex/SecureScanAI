import 'package:flutter/material.dart';

import '../core/api_client.dart';
import '../core/app_info.dart';
import '../core/app_state.dart';
import '../core/url_rules.dart';
import 'theme.dart';
import 'widgets.dart';

/// Splash screen; also shows a retry panel when the saved server cannot be reached.
class SplashScreen extends StatelessWidget {
  const SplashScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final state = AppScope.of(context);
    final c = AppColors.of(context);
    final offline = state.phase == BootPhase.offline;
    return Scaffold(
      body: SafeArea(
        child: Center(
          child: Padding(
            padding: const EdgeInsets.all(28),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                const BrandMark(size: 96),
                const SizedBox(height: 18),
                const Text(
                  kAppName,
                  style: TextStyle(
                    fontSize: 28,
                    fontWeight: FontWeight.w800,
                    letterSpacing: -0.5,
                  ),
                ),
                const SizedBox(height: 4),
                Text(
                  'Vulnerability assessment',
                  style: TextStyle(color: c.muted),
                ),
                const SizedBox(height: 30),
                if (!offline)
                  const SizedBox(
                    width: 26,
                    height: 26,
                    child: CircularProgressIndicator(strokeWidth: 3),
                  ),
                if (offline) ...[
                  Banner2(
                    state.bootError ?? 'The server could not be reached.',
                    error: true,
                    icon: Icons.cloud_off_outlined,
                  ),
                  const SizedBox(height: 16),
                  Wrap(
                    spacing: 10,
                    runSpacing: 10,
                    alignment: WrapAlignment.center,
                    children: [
                      FilledButton.icon(
                        onPressed: state.init,
                        icon: const Icon(Icons.refresh),
                        label: const Text('Retry connection'),
                      ),
                      OutlinedButton.icon(
                        onPressed: () => Navigator.of(context).push(
                          MaterialPageRoute<void>(
                            builder: (_) => const ServerScreen(firstRun: false),
                          ),
                        ),
                        icon: const Icon(Icons.dns_outlined),
                        label: const Text('Server settings'),
                      ),
                    ],
                  ),
                  const SizedBox(height: 8),
                  Text(
                    state.serverUrl ?? '',
                    style: TextStyle(color: c.faint, fontSize: 12),
                  ),
                ],
              ],
            ),
          ),
        ),
      ),
    );
  }
}

/// Enter / change the backend address, test it and save it.
class ServerScreen extends StatefulWidget {
  const ServerScreen({super.key, required this.firstRun});
  final bool firstRun;

  @override
  State<ServerScreen> createState() => _ServerScreenState();
}

class _ServerScreenState extends State<ServerScreen> {
  final TextEditingController _url = TextEditingController();
  String? _error;
  String? _okMessage;
  bool _testing = false;

  @override
  void initState() {
    super.initState();
    // initState may not subscribe to inherited widgets, so read without registering a dependency
    final state = context.getInheritedWidgetOfExactType<AppScope>()!.notifier!;
    _url.text = state.serverUrl ?? kDefaultServer;
  }

  @override
  void dispose() {
    _url.dispose();
    super.dispose();
  }

  Future<String?> _validateAndTest() async {
    setState(() {
      _error = null;
      _okMessage = null;
      _testing = true;
    });
    final check = normalizeServerUrl(_url.text);
    if (!check.isValid) {
      setState(() {
        _error = check.error;
        _testing = false;
      });
      return null;
    }
    final probe = ApiClient(baseUrl: check.url!);
    try {
      final info = await probe.health();
      if (!mounted) return null;
      setState(
        () => _okMessage = 'Connected: ${info['app']} ${info['version']}',
      );
      return check.url;
    } on ApiException catch (e) {
      if (mounted) setState(() => _error = e.message);
      return null;
    } finally {
      probe.close();
      if (mounted) setState(() => _testing = false);
    }
  }

  Future<void> _save() async {
    final state = AppScope.of(context);
    final nav = Navigator.of(context);
    final url = _url.text.trim().isEmpty ? null : normalizeServerUrl(_url.text);
    if (url == null || !url.isValid) {
      setState(() => _error = url?.error ?? 'Enter the server address.');
      return;
    }
    if (state.signedIn && state.serverUrl != url.url) {
      final ok = await showDialog<bool>(
        context: context,
        builder: (ctx) => AlertDialog(
          title: const Text('Change server?'),
          content: const Text(
            'You will be signed out because the new server has its own accounts.',
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(ctx, false),
              child: const Text('Cancel'),
            ),
            FilledButton(
              onPressed: () => Navigator.pop(ctx, true),
              child: const Text('Change'),
            ),
          ],
        ),
      );
      if (ok != true) return;
    }
    await state.setServer(url.url!);
    if (!mounted) return;
    if (nav.canPop()) nav.pop();
  }

  @override
  Widget build(BuildContext context) {
    final c = AppColors.of(context);
    return Scaffold(
      appBar: widget.firstRun
          ? null
          : AppBar(title: const Text('Server settings')),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.all(22),
          children: [
            if (widget.firstRun) ...[
              const SizedBox(height: 24),
              const Center(child: BrandMark(size: 72)),
              const SizedBox(height: 16),
              const Text(
                'Connect to your server',
                textAlign: TextAlign.center,
                style: TextStyle(fontSize: 24, fontWeight: FontWeight.w800),
              ),
              const SizedBox(height: 8),
            ],
            Text(
              'Enter the address of the SecureScan AI server running on your Windows computer. '
              'Your phone and the computer must be on the same Wi-Fi network.',
              textAlign: widget.firstRun ? TextAlign.center : TextAlign.start,
              style: TextStyle(color: c.muted, height: 1.4),
            ),
            const SizedBox(height: 22),
            TextField(
              controller: _url,
              keyboardType: TextInputType.url,
              autocorrect: false,
              enableSuggestions: false,
              textInputAction: TextInputAction.done,
              onSubmitted: (_) => _validateAndTest(),
              decoration: InputDecoration(
                labelText: 'Server address',
                hintText: 'http://192.168.1.20:8000',
                prefixIcon: const Icon(Icons.dns_outlined),
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(14),
                ),
              ),
            ),
            const SizedBox(height: 12),
            if (_error != null)
              Banner2(_error!, error: true, icon: Icons.error_outline),
            if (_okMessage != null)
              Banner2(_okMessage!, icon: Icons.check_circle_outline),
            const SizedBox(height: 14),
            Row(
              children: [
                Expanded(
                  child: OutlinedButton.icon(
                    onPressed: _testing ? null : _validateAndTest,
                    icon: _testing
                        ? const SizedBox(
                            width: 16,
                            height: 16,
                            child: CircularProgressIndicator(strokeWidth: 2),
                          )
                        : const Icon(Icons.wifi_tethering),
                    label: const Text('Test connection'),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: FilledButton.icon(
                    onPressed: _testing ? null : _save,
                    icon: const Icon(Icons.check),
                    label: const Text('Save'),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 26),
            AppCard(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text(
                    'How to find the address',
                    style: TextStyle(fontWeight: FontWeight.w800),
                  ),
                  const SizedBox(height: 8),
                  Text(
                    '1. On the Windows computer open Command Prompt and run: ipconfig\n'
                    '2. Copy the "IPv4 Address" of your Wi-Fi adapter, for example 192.168.1.20.\n'
                    '3. Type it here with the port: http://192.168.1.20:8000\n\n'
                    'Never use "localhost" on the phone - it means the phone itself. '
                    'Plain http:// works only for private network addresses; use https:// for anything else. '
                    'Certificates are always verified.',
                    style: TextStyle(
                      color: c.muted,
                      height: 1.45,
                      fontSize: 13.5,
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class LoginScreen extends StatefulWidget {
  const LoginScreen({super.key});

  @override
  State<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends State<LoginScreen> {
  final TextEditingController _user = TextEditingController();
  final TextEditingController _pass = TextEditingController();
  bool _busy = false;
  bool _show = false;
  String? _error;
  String? _connection; // null = checking
  bool _connectionOk = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _checkConnection());
  }

  @override
  void dispose() {
    _user.dispose();
    _pass.dispose();
    super.dispose();
  }

  Future<void> _checkConnection() async {
    final state = AppScope.of(context);
    setState(() => _connection = null);
    final probe = ApiClient(baseUrl: state.serverUrl!);
    try {
      final info = await probe.health();
      if (mounted) {
        setState(() {
          _connection = 'Connected - ${info['app']} ${info['version']}';
          _connectionOk = true;
        });
      }
    } on ApiException catch (e) {
      if (mounted) {
        setState(() {
          _connection = e.message;
          _connectionOk = false;
        });
      }
    } finally {
      probe.close();
    }
  }

  Future<void> _signIn() async {
    if (_user.text.trim().isEmpty || _pass.text.isEmpty) {
      setState(() => _error = 'Enter your username and password.');
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await AppScope.of(context).login(_user.text, _pass.text);
    } on ApiException catch (e) {
      if (mounted) {
        setState(() {
          _error = e.message;
          _pass.clear();
        });
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final state = AppScope.of(context);
    final c = AppColors.of(context);
    return Scaffold(
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(24),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 420),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  const Center(child: BrandMark(size: 68)),
                  const SizedBox(height: 14),
                  const Text(
                    'Sign in',
                    textAlign: TextAlign.center,
                    style: TextStyle(fontSize: 28, fontWeight: FontWeight.w800),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    'Use the account created by your administrator.',
                    textAlign: TextAlign.center,
                    style: TextStyle(color: c.muted),
                  ),
                  const SizedBox(height: 22),
                  if (state.notice != null) ...[
                    Banner2(state.notice!, icon: Icons.lock_clock_outlined),
                    const SizedBox(height: 12),
                  ],
                  TextField(
                    controller: _user,
                    autocorrect: false,
                    enableSuggestions: false,
                    textInputAction: TextInputAction.next,
                    autofillHints: const [AutofillHints.username],
                    decoration: InputDecoration(
                      labelText: 'Username',
                      prefixIcon: const Icon(Icons.person_outline),
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(14),
                      ),
                    ),
                  ),
                  const SizedBox(height: 14),
                  TextField(
                    controller: _pass,
                    obscureText: !_show,
                    autofillHints: const [AutofillHints.password],
                    onSubmitted: (_) => _signIn(),
                    decoration: InputDecoration(
                      labelText: 'Password',
                      prefixIcon: const Icon(Icons.lock_outline),
                      suffixIcon: IconButton(
                        onPressed: () => setState(() => _show = !_show),
                        icon: Icon(
                          _show ? Icons.visibility_off : Icons.visibility,
                        ),
                      ),
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(14),
                      ),
                    ),
                  ),
                  if (_error != null) ...[
                    const SizedBox(height: 12),
                    Banner2(_error!, error: true, icon: Icons.error_outline),
                  ],
                  const SizedBox(height: 18),
                  SizedBox(
                    height: 50,
                    child: FilledButton(
                      onPressed: _busy ? null : _signIn,
                      child: _busy
                          ? const SizedBox(
                              width: 22,
                              height: 22,
                              child: CircularProgressIndicator(
                                strokeWidth: 2.5,
                              ),
                            )
                          : const Text(
                              'Sign in',
                              style: TextStyle(
                                fontSize: 16,
                                fontWeight: FontWeight.w700,
                              ),
                            ),
                    ),
                  ),
                  const SizedBox(height: 22),
                  AppCard(
                    padding: const EdgeInsets.all(12),
                    child: Row(
                      children: [
                        Container(
                          width: 10,
                          height: 10,
                          decoration: BoxDecoration(
                            shape: BoxShape.circle,
                            color: _connection == null
                                ? c.faint
                                : (_connectionOk ? c.ok : c.bad),
                          ),
                        ),
                        const SizedBox(width: 10),
                        Expanded(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text(
                                state.serverUrl ?? '',
                                maxLines: 1,
                                overflow: TextOverflow.ellipsis,
                                style: const TextStyle(
                                  fontWeight: FontWeight.w700,
                                  fontSize: 13,
                                ),
                              ),
                              Text(
                                _connection ?? 'Checking connection...',
                                maxLines: 2,
                                overflow: TextOverflow.ellipsis,
                                style: TextStyle(color: c.muted, fontSize: 12),
                              ),
                            ],
                          ),
                        ),
                        IconButton(
                          tooltip: 'Retry connection',
                          onPressed: _checkConnection,
                          icon: const Icon(Icons.refresh),
                        ),
                        IconButton(
                          tooltip: 'Server settings',
                          onPressed: () async {
                            await Navigator.of(context).push(
                              MaterialPageRoute<void>(
                                builder: (_) =>
                                    const ServerScreen(firstRun: false),
                              ),
                            );
                            if (mounted) _checkConnection();
                          },
                          icon: const Icon(Icons.dns_outlined),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class ChangePasswordScreen extends StatelessWidget {
  const ChangePasswordScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final state = AppScope.of(context);
    return Scaffold(
      appBar: AppBar(
        title: const Text('Choose a new password'),
        actions: [
          TextButton(onPressed: state.logout, child: const Text('Sign out')),
        ],
      ),
      body: const SafeArea(
        child: SingleChildScrollView(
          padding: EdgeInsets.all(22),
          child: PasswordForm(forced: true),
        ),
      ),
    );
  }
}

class PasswordForm extends StatefulWidget {
  const PasswordForm({super.key, this.forced = false, this.onDone});
  final bool forced;
  final VoidCallback? onDone;

  @override
  State<PasswordForm> createState() => _PasswordFormState();
}

class _PasswordFormState extends State<PasswordForm> {
  final TextEditingController _cur = TextEditingController();
  final TextEditingController _n1 = TextEditingController();
  final TextEditingController _n2 = TextEditingController();
  bool _busy = false;
  String? _error;

  @override
  void dispose() {
    _cur.dispose();
    _n1.dispose();
    _n2.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    if (_n1.text != _n2.text) {
      setState(() => _error = 'The new passwords do not match.');
      return;
    }
    final state = AppScope.of(context);
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final user = await state.api.changePassword(_cur.text, _n1.text);
      state.updateUser(user);
      if (!mounted) return;
      showMessage(context, 'Password updated');
      widget.onDone?.call();
    } on ApiException catch (e) {
      if (mounted) setState(() => _error = e.message);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  InputDecoration _deco(String label) => InputDecoration(
    labelText: label,
    border: OutlineInputBorder(borderRadius: BorderRadius.circular(14)),
  );

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        if (widget.forced) ...[
          const Banner2(
            'Your administrator requires a new password before you continue.',
          ),
          const SizedBox(height: 16),
        ],
        TextField(
          controller: _cur,
          obscureText: true,
          decoration: _deco(
            widget.forced ? 'Current (temporary) password' : 'Current password',
          ),
        ),
        const SizedBox(height: 12),
        TextField(
          controller: _n1,
          obscureText: true,
          decoration: _deco(
            'New password (12+ characters, letters and numbers)',
          ),
        ),
        const SizedBox(height: 12),
        TextField(
          controller: _n2,
          obscureText: true,
          decoration: _deco('Repeat new password'),
        ),
        if (_error != null) ...[
          const SizedBox(height: 12),
          Banner2(_error!, error: true, icon: Icons.error_outline),
        ],
        const SizedBox(height: 16),
        SizedBox(
          height: 48,
          child: FilledButton(
            onPressed: _busy ? null : _submit,
            child: _busy
                ? const SizedBox(
                    width: 20,
                    height: 20,
                    child: CircularProgressIndicator(strokeWidth: 2.5),
                  )
                : const Text('Update password'),
          ),
        ),
      ],
    );
  }
}
