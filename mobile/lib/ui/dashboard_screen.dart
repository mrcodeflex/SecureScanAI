import 'dart:async';

import 'package:flutter/material.dart';

import '../core/api_client.dart';
import '../core/app_state.dart';
import '../core/format.dart';
import '../core/models.dart';
import 'scan_detail_screen.dart';
import 'theme.dart';
import 'widgets.dart';

class DashboardScreen extends StatefulWidget {
  const DashboardScreen({
    super.key,
    required this.active,
    required this.onNewScan,
  });
  final bool active;
  final VoidCallback onNewScan;

  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen> {
  Dashboard? _data;
  String? _error;
  Timer? _timer;
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _load());
  }

  @override
  void didUpdateWidget(covariant DashboardScreen old) {
    super.didUpdateWidget(old);
    if (widget.active && !old.active) _load(silent: true);
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  Future<void> _load({bool silent = false}) async {
    _timer?.cancel();
    if (!silent) setState(() => _loading = true);
    try {
      final d = await AppScope.of(context).api.dashboard();
      if (!mounted) return;
      setState(() {
        _data = d;
        _error = null;
        _loading = false;
      });
      if (d.running > 0) {
        _timer = Timer(const Duration(seconds: 3), () => _load(silent: true));
      }
    } on ApiException catch (e) {
      if (mounted) {
        setState(() {
          _error = e.message;
          _loading = false;
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final user = AppScope.of(context).user!;
    final c = AppColors.of(context);
    final d = _data;
    if (_loading && d == null) return const Loading();
    if (d == null) {
      return ErrorView(
        message: _error ?? 'Could not load the dashboard.',
        onRetry: _load,
      );
    }
    return RefreshIndicator(
      onRefresh: () => _load(silent: true),
      child: ListView(
        physics: const AlwaysScrollableScrollPhysics(),
        padding: const EdgeInsets.fromLTRB(16, 14, 16, 24),
        children: [
          Text('Welcome back,', style: TextStyle(color: c.muted)),
          Text(
            user.displayName,
            style: const TextStyle(
              fontSize: 26,
              fontWeight: FontWeight.w800,
              letterSpacing: -0.5,
            ),
          ),
          const SizedBox(height: 4),
          Text(
            d.scope == 'all'
                ? 'Overview of all scans on this server'
                : 'Overview of your scans',
            style: TextStyle(color: c.muted, fontSize: 13),
          ),
          const SizedBox(height: 16),
          if (_error != null) ...[
            Banner2(_error!, error: true),
            const SizedBox(height: 12),
          ],
          Row(
            children: [
              Expanded(
                child: _Kpi(
                  'Total scans',
                  '${d.totalScans}',
                  Icons.radar,
                  c.brand,
                  sub: d.running > 0 ? '${d.running} running' : null,
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: _Kpi(
                  'Completed',
                  '${d.completed}',
                  Icons.check_circle_outline,
                  c.ok,
                ),
              ),
            ],
          ),
          const SizedBox(height: 12),
          Row(
            children: [
              Expanded(
                child: _Kpi(
                  'Failed',
                  '${d.failed}',
                  Icons.error_outline,
                  c.bad,
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: _Kpi(
                  'Avg. score',
                  d.averageScore == null ? '-' : '${d.averageScore}',
                  Icons.shield_outlined,
                  AppColors.score(d.averageScore, c),
                ),
              ),
            ],
          ),
          if (user.canScan) ...[
            const SizedBox(height: 14),
            SizedBox(
              height: 50,
              child: FilledButton.icon(
                onPressed: widget.onNewScan,
                icon: const Icon(Icons.add),
                label: const Text(
                  'New scan',
                  style: TextStyle(fontSize: 16, fontWeight: FontWeight.w700),
                ),
              ),
            ),
          ],
          const SectionTitle('Findings by severity'),
          AppCard(
            child: Row(
              children: [
                SeverityDonut(counts: d.severity, size: 140),
                const SizedBox(width: 18),
                Expanded(
                  child: Column(
                    children: [
                      for (final k in severityOrder)
                        Padding(
                          padding: const EdgeInsets.symmetric(vertical: 4),
                          child: Row(
                            children: [
                              Container(
                                width: 10,
                                height: 10,
                                decoration: BoxDecoration(
                                  color: AppColors.severity(k),
                                  borderRadius: BorderRadius.circular(3),
                                ),
                              ),
                              const SizedBox(width: 8),
                              Expanded(
                                child: Text(
                                  severityLabels[k]!,
                                  style: TextStyle(color: c.muted),
                                ),
                              ),
                              Text(
                                '${d.severity[k] ?? 0}',
                                style: const TextStyle(
                                  fontWeight: FontWeight.w800,
                                ),
                              ),
                            ],
                          ),
                        ),
                    ],
                  ),
                ),
              ],
            ),
          ),
          if (d.categories.isNotEmpty) ...[
            const SectionTitle('Most frequent categories'),
            AppCard(
              child: Column(
                children: [
                  for (final cat in d.categories)
                    _CategoryBar(cat, d.categories.first.count),
                ],
              ),
            ),
          ],
          SectionTitle('Recent scans'),
          if (d.recent.isEmpty)
            const AppCard(
              child: Padding(
                padding: EdgeInsets.all(8),
                child: EmptyState(
                  icon: Icons.radar,
                  title: 'No scans yet',
                  message: 'Run your first scan to see results here.',
                ),
              ),
            )
          else
            for (final s in d.recent)
              Padding(
                padding: const EdgeInsets.only(bottom: 10),
                child: ScanRow(
                  scan: s,
                  subtitle:
                      '${s.isWebsite ? 'Website' : 'Source ZIP'} - ${timeAgo(s.createdAt)}',
                  onTap: () => Navigator.of(context).push(
                    MaterialPageRoute<void>(
                      builder: (_) => ScanDetailScreen(scanId: s.id),
                    ),
                  ),
                ),
              ),
        ],
      ),
    );
  }
}

class _Kpi extends StatelessWidget {
  const _Kpi(this.label, this.value, this.icon, this.color, {this.sub});
  final String label;
  final String value;
  final IconData icon;
  final Color color;
  final String? sub;

  @override
  Widget build(BuildContext context) {
    final c = AppColors.of(context);
    return AppCard(
      accent: color,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(icon, size: 16, color: color),
              const SizedBox(width: 6),
              Expanded(
                child: Text(
                  label,
                  style: TextStyle(
                    color: c.muted,
                    fontSize: 12.5,
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 6),
          Text(
            value,
            style: const TextStyle(
              fontSize: 30,
              fontWeight: FontWeight.w800,
              height: 1.1,
            ),
          ),
          if (sub != null)
            Text(sub!, style: TextStyle(color: c.faint, fontSize: 12)),
        ],
      ),
    );
  }
}

class _CategoryBar extends StatelessWidget {
  const _CategoryBar(this.cat, this.max);
  final CategoryCount cat;
  final int max;

  @override
  Widget build(BuildContext context) {
    final c = AppColors.of(context);
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: Row(
        children: [
          SizedBox(
            width: 110,
            child: Text(
              cat.name,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: TextStyle(color: c.muted, fontSize: 13),
            ),
          ),
          Expanded(
            child: ClipRRect(
              borderRadius: BorderRadius.circular(99),
              child: LinearProgressIndicator(
                value: max == 0 ? 0 : cat.count / max,
                minHeight: 9,
                backgroundColor: c.line,
                color: c.brand,
              ),
            ),
          ),
          const SizedBox(width: 10),
          Text(
            '${cat.count}',
            style: const TextStyle(fontWeight: FontWeight.w800),
          ),
        ],
      ),
    );
  }
}
