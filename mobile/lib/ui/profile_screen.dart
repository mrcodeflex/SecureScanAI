import 'package:flutter/material.dart';

import '../core/api_client.dart';
import '../core/app_info.dart';
import '../core/app_state.dart';
import '../core/models.dart';
import 'auth_screens.dart';
import 'theme.dart';
import 'widgets.dart';

class ProfileScreen extends StatefulWidget {
  const ProfileScreen({super.key});

  @override
  State<ProfileScreen> createState() => _ProfileScreenState();
}

class _ProfileScreenState extends State<ProfileScreen> {
  String? _connection;
  bool _connectionOk = false;
  bool _checking = false;
  List<EngineInfo>? _engines;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _check();
      _loadEngines();
    });
  }

  Future<void> _check() async {
    final state = AppScope.of(context);
    setState(() => _checking = true);
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
      if (mounted) setState(() => _checking = false);
    }
  }

  Future<void> _loadEngines() async {
    try {
      final list = await AppScope.of(context).api.engines();
      if (mounted) setState(() => _engines = list);
    } on ApiException {
      // engine list is informational only
    }
  }

  void _changePassword() {
    showModalBottomSheet<void>(
      context: context,
      isScrollControlled: true,
      showDragHandle: true,
      builder: (ctx) => Padding(
        padding: EdgeInsets.fromLTRB(
          20,
          4,
          20,
          20 + MediaQuery.of(ctx).viewInsets.bottom,
        ),
        child: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text(
                'Change password',
                style: TextStyle(fontSize: 20, fontWeight: FontWeight.w800),
              ),
              const SizedBox(height: 14),
              PasswordForm(onDone: () => Navigator.pop(ctx)),
            ],
          ),
        ),
      ),
    );
  }

  Future<void> _signOut() async {
    final state = AppScope.of(context);
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Sign out?'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('Sign out'),
          ),
        ],
      ),
    );
    if (ok == true) await state.logout();
  }

  @override
  Widget build(BuildContext context) {
    final state = AppScope.of(context);
    final user = state.user!;
    final c = AppColors.of(context);
    return ListView(
      padding: const EdgeInsets.fromLTRB(16, 14, 16, 28),
      children: [
        const Text(
          'Profile',
          style: TextStyle(
            fontSize: 26,
            fontWeight: FontWeight.w800,
            letterSpacing: -0.5,
          ),
        ),
        const SizedBox(height: 14),
        AppCard(
          child: Row(
            children: [
              CircleAvatar(
                radius: 28,
                backgroundColor: c.brand,
                child: Text(
                  user.displayName
                      .substring(
                        0,
                        user.displayName.length < 2
                            ? user.displayName.length
                            : 2,
                      )
                      .toUpperCase(),
                  style: const TextStyle(
                    color: Colors.white,
                    fontWeight: FontWeight.w800,
                    fontSize: 18,
                  ),
                ),
              ),
              const SizedBox(width: 14),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      user.displayName,
                      style: const TextStyle(
                        fontSize: 18,
                        fontWeight: FontWeight.w800,
                      ),
                    ),
                    Text('@${user.username}', style: TextStyle(color: c.muted)),
                    const SizedBox(height: 4),
                    Text(
                      user.roleLabel,
                      style: TextStyle(
                        color: c.brand,
                        fontWeight: FontWeight.w700,
                        fontSize: 13,
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
        const SectionTitle('Server connection'),
        AppCard(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
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
                    child: Text(
                      state.serverUrl ?? '',
                      style: const TextStyle(fontWeight: FontWeight.w700),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 6),
              Text(
                _checking ? 'Checking...' : (_connection ?? '-'),
                style: TextStyle(color: c.muted, fontSize: 13),
              ),
              const SizedBox(height: 12),
              Row(
                children: [
                  Expanded(
                    child: OutlinedButton.icon(
                      onPressed: _checking ? null : _check,
                      icon: const Icon(Icons.refresh),
                      label: const Text('Retry'),
                    ),
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: OutlinedButton.icon(
                      onPressed: () => Navigator.of(context)
                          .push(
                            MaterialPageRoute<void>(
                              builder: (_) =>
                                  const ServerScreen(firstRun: false),
                            ),
                          )
                          .then((_) => _check()),
                      icon: const Icon(Icons.dns_outlined),
                      label: const Text('Change'),
                    ),
                  ),
                ],
              ),
            ],
          ),
        ),
        const SectionTitle('Account'),
        AppCard(
          padding: EdgeInsets.zero,
          child: Column(
            children: [
              ListTile(
                leading: const Icon(Icons.key_outlined),
                title: const Text('Change password'),
                trailing: const Icon(Icons.chevron_right),
                onTap: _changePassword,
              ),
              Divider(height: 1, color: c.line),
              ListTile(
                leading: Icon(Icons.logout, color: c.bad),
                title: Text(
                  'Sign out',
                  style: TextStyle(color: c.bad, fontWeight: FontWeight.w700),
                ),
                onTap: _signOut,
              ),
            ],
          ),
        ),
        if (_engines != null) ...[
          const SectionTitle('Scan engines on the server'),
          AppCard(
            child: Column(
              children: [
                for (final e in _engines!)
                  Padding(
                    padding: const EdgeInsets.symmetric(vertical: 5),
                    child: Row(
                      children: [
                        Expanded(
                          child: Text(
                            e.name,
                            style: const TextStyle(fontSize: 13.5),
                          ),
                        ),
                        Text(
                          e.state.replaceAll('_', ' '),
                          style: TextStyle(
                            color:
                                (e.state == 'installed' ||
                                    e.state == 'available')
                                ? c.ok
                                : c.warn,
                            fontWeight: FontWeight.w700,
                            fontSize: 12.5,
                          ),
                        ),
                      ],
                    ),
                  ),
              ],
            ),
          ),
        ],
        const SizedBox(height: 22),
        Center(
          child: Text(
            '$kAppName $kAppVersion',
            style: TextStyle(color: c.faint, fontSize: 12.5),
          ),
        ),
        const SizedBox(height: 4),
        Center(
          child: Text(
            'Scan only systems you own or are authorized to test.',
            style: TextStyle(color: c.faint, fontSize: 12),
          ),
        ),
      ],
    );
  }
}
