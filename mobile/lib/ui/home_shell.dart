import 'package:flutter/material.dart';

import '../core/app_state.dart';
import 'dashboard_screen.dart';
import 'history_screen.dart';
import 'new_scan_screen.dart';
import 'profile_screen.dart';

/// Bottom-navigation shell. Android back from a non-home tab returns to the dashboard first.
class HomeShell extends StatefulWidget {
  const HomeShell({super.key});

  @override
  State<HomeShell> createState() => _HomeShellState();
}

class _HomeShellState extends State<HomeShell> {
  int _index = 0;

  @override
  Widget build(BuildContext context) {
    final user = AppScope.of(context).user!;
    final tabs = <_Tab>[
      _Tab(
        'Dashboard',
        Icons.space_dashboard_outlined,
        Icons.space_dashboard,
        (active) =>
            DashboardScreen(active: active, onNewScan: () => _go('scan')),
      ),
      if (user.canScan)
        _Tab(
          'Scan',
          Icons.radar_outlined,
          Icons.radar,
          (active) => const NewScanScreen(),
          key: 'scan',
        ),
      _Tab(
        'History',
        Icons.history,
        Icons.history,
        (active) => HistoryScreen(active: active),
        key: 'history',
      ),
      _Tab(
        'Profile',
        Icons.person_outline,
        Icons.person,
        (active) => const ProfileScreen(),
        key: 'profile',
      ),
    ];
    if (_index >= tabs.length) _index = 0;
    return PopScope(
      canPop: _index == 0,
      onPopInvokedWithResult: (didPop, result) {
        if (!didPop) setState(() => _index = 0);
      },
      child: Scaffold(
        body: SafeArea(
          bottom: false,
          child: IndexedStack(
            index: _index,
            children: [
              for (var i = 0; i < tabs.length; i++)
                tabs[i].builder(i == _index),
            ],
          ),
        ),
        bottomNavigationBar: NavigationBar(
          selectedIndex: _index,
          onDestinationSelected: (i) => setState(() => _index = i),
          destinations: [
            for (final t in tabs)
              NavigationDestination(
                icon: Icon(t.icon),
                selectedIcon: Icon(t.selectedIcon),
                label: t.label,
              ),
          ],
        ),
      ),
    );
  }

  void _go(String key) {
    final user = AppScope.of(context).user!;
    final keys = ['dashboard', if (user.canScan) 'scan', 'history', 'profile'];
    final i = keys.indexOf(key);
    if (i >= 0) setState(() => _index = i);
  }
}

class _Tab {
  _Tab(
    this.label,
    this.icon,
    this.selectedIcon,
    this.builder, {
    this.key = 'dashboard',
  });
  final String label;
  final IconData icon;
  final IconData selectedIcon;
  final Widget Function(bool active) builder;
  final String key;
}
