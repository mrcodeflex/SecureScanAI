import 'package:flutter/material.dart';

import 'core/app_info.dart';
import 'core/app_state.dart';
import 'ui/auth_screens.dart';
import 'ui/home_shell.dart';
import 'ui/theme.dart';

class SecureScanApp extends StatefulWidget {
  const SecureScanApp({super.key});

  @override
  State<SecureScanApp> createState() => _SecureScanAppState();
}

class _SecureScanAppState extends State<SecureScanApp> {
  final AppState _state = AppState();

  @override
  void initState() {
    super.initState();
    _state.init();
  }

  @override
  void dispose() {
    _state.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AppScope(
      state: _state,
      child: MaterialApp(
        title: kAppName,
        debugShowCheckedModeBanner: false,
        navigatorKey: _state.navigatorKey,
        theme: buildTheme(Brightness.light),
        darkTheme: buildTheme(Brightness.dark),
        themeMode: ThemeMode.system,
        home: const _Root(),
      ),
    );
  }
}

/// Chooses the screen from the state: splash -> server setup -> login -> forced password change -> app.
class _Root extends StatelessWidget {
  const _Root();

  @override
  Widget build(BuildContext context) {
    final state = AppScope.of(context);
    if (state.phase != BootPhase.ready) return const SplashScreen();
    if (!state.hasServer) return const ServerScreen(firstRun: true);
    if (!state.signedIn) return const LoginScreen();
    if (state.user!.mustChangePassword) return const ChangePasswordScreen();
    return const HomeShell();
  }
}
