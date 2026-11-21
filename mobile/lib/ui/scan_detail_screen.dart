import 'dart:async';

import 'package:flutter/material.dart';
import 'package:open_filex/open_filex.dart';

import '../core/api_client.dart';
import '../core/app_state.dart';
import '../core/format.dart';
import '../core/models.dart';
import 'theme.dart';
import 'widgets.dart';

class ScanDetailScreen extends StatefulWidget {
  const ScanDetailScreen({super.key, required this.scanId});
  final String scanId;

  @override
  State<ScanDetailScreen> createState() => _ScanDetailScreenState();
}

class _ScanDetailScreenState extends State<ScanDetailScreen> {
  Scan? _scan;
  String? _error;
  Timer? _timer;
  bool _technical = false;
  bool _modeSet = false;
  String? _severityFilter;
  String? _downloading;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _load());
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  Future<void> _load() async {
    _timer?.cancel();
    try {
      final scan = await AppScope.of(context).api.getScan(widget.scanId);
      if (!mounted) return;
      setState(() {
        _scan = scan;
        _error = null;
        if (!_modeSet) {
          _technical = scan.mode == 'advanced';
          _modeSet = true;
        }
      });
      if (scan.isRunning) {
        _timer = Timer(const Duration(milliseconds: 1500), _load);
      }
    } on ApiException catch (e) {
      if (mounted) setState(() => _error = e.message);
    }
  }

  Future<void> _cancel() async {
    try {
      await AppScope.of(context).api.cancelScan(widget.scanId);
      if (mounted) showMessage(context, 'Cancelling...');
      _load();
    } on ApiException catch (e) {
      if (mounted) showMessage(context, e.message, error: true);
    }
  }

  Future<void> _delete() async {
    final api = AppScope.of(context).api;
    final nav = Navigator.of(context);
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Delete this scan?'),
        content: const Text(
          'The scan, its findings and reports will be permanently removed.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('Delete'),
          ),
        ],
      ),
    );
    if (ok != true) return;
    try {
      await api.deleteScan(widget.scanId);
      if (!mounted) return;
      showMessage(context, 'Scan deleted');
      nav.pop();
    } on ApiException catch (e) {
      if (mounted) showMessage(context, e.message, error: true);
    }
  }

  Future<void> _download(String format) async {
    final scan = _scan!;
    setState(() => _downloading = format);
    try {
      final file = await AppScope.of(
        context,
      ).api.downloadReport(scan.id, format, scan.reportId);
      if (!mounted) return;
      showMessage(context, '${format.toUpperCase()} report saved');
      final result = await OpenFilex.open(file.path);
      if (!mounted) return;
      if (result.type != ResultType.done) {
        showMessage(
          context,
          'Saved to ${file.path}. No app was found to open a .$format file.',
          error: result.type != ResultType.noAppToOpen,
        );
      }
    } on ApiException catch (e) {
      if (mounted) showMessage(context, e.message, error: true);
    } finally {
      if (mounted) setState(() => _downloading = null);
    }
  }

  @override
  Widget build(BuildContext context) {
    final scan = _scan;
    final user = AppScope.of(context).user!;
    return Scaffold(
      appBar: AppBar(
        title: Text(scan?.title ?? 'Scan', overflow: TextOverflow.ellipsis),
        actions: [
          if (scan != null && !scan.isRunning && user.canScan)
            IconButton(
              tooltip: 'Delete scan',
              onPressed: _delete,
              icon: const Icon(Icons.delete_outline),
            ),
        ],
      ),
      body: SafeArea(child: _body(scan, user)),
    );
  }

  Widget _body(Scan? scan, AppUser user) {
    if (scan == null) {
      return _error != null
          ? ErrorView(message: _error!, onRetry: _load)
          : const Loading();
    }
    if (scan.isRunning) return _running(scan, user);
    if (!scan.isCompleted) return _ended(scan);
    return _results(scan);
  }

  Widget _running(Scan scan, AppUser user) {
    final c = AppColors.of(context);
    return ListView(
      padding: const EdgeInsets.all(20),
      children: [
        const SizedBox(height: 20),
        Center(
          child: SizedBox(
            width: 170,
            height: 170,
            child: Stack(
              alignment: Alignment.center,
              children: [
                SizedBox(
                  width: 170,
                  height: 170,
                  child: CircularProgressIndicator(
                    value: scan.progress <= 2 ? null : scan.progress / 100,
                    strokeWidth: 9,
                    backgroundColor: c.line,
                  ),
                ),
                Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Text(
                      '${scan.progress}%',
                      style: const TextStyle(
                        fontSize: 38,
                        fontWeight: FontWeight.w800,
                      ),
                    ),
                    Text(
                      scan.status == 'queued' ? 'Waiting' : 'Scanning',
                      style: TextStyle(color: c.muted),
                    ),
                  ],
                ),
              ],
            ),
          ),
        ),
        const SizedBox(height: 24),
        Text(
          scan.progressMessage,
          textAlign: TextAlign.center,
          style: const TextStyle(fontSize: 15, fontWeight: FontWeight.w600),
        ),
        const SizedBox(height: 6),
        Text(
          'Elapsed: ${formatDuration(scan.startedAt ?? scan.createdAt, null)}',
          textAlign: TextAlign.center,
          style: TextStyle(color: c.faint),
        ),
        const SizedBox(height: 22),
        const Banner2(
          'You can leave this screen. The scan keeps running on the server and appears in your history.',
        ),
        const SizedBox(height: 18),
        if (user.canScan)
          OutlinedButton.icon(
            onPressed: _cancel,
            icon: const Icon(Icons.stop_circle_outlined),
            label: const Text('Cancel scan'),
          ),
      ],
    );
  }

  Widget _ended(Scan scan) => EmptyState(
    icon: scan.status == 'failed' ? Icons.error_outline : Icons.cancel_outlined,
    title: scan.status == 'failed'
        ? 'The scan could not be completed'
        : 'The scan was cancelled',
    message: scan.error ?? 'No results were saved.',
  );

  Widget _results(Scan scan) {
    final c = AppColors.of(context);
    final shown = scan.findings
        .where((f) => _severityFilter == null || f.severity == _severityFilter)
        .toList();
    final riskColor =
        {
          'minimal': c.ok,
          'low': c.ok,
          'medium': AppColors.severity('medium'),
        }[scan.riskLevel] ??
        AppColors.severity('critical');
    return RefreshIndicator(
      onRefresh: _load,
      child: ListView(
        physics: const AlwaysScrollableScrollPhysics(),
        padding: const EdgeInsets.fromLTRB(16, 8, 16, 28),
        children: [
          Text(
            '${scan.isWebsite ? 'Website scan' : 'Source code scan'} - ${scan.mode} mode',
            style: TextStyle(color: c.muted, fontSize: 13),
          ),
          Text(scan.reportId, style: TextStyle(color: c.faint, fontSize: 12)),
          const SizedBox(height: 12),
          AppCard(
            child: Row(
              children: [
                ScoreRing(score: scan.score, size: 112),
                const SizedBox(width: 18),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Overall risk',
                        style: TextStyle(color: c.muted, fontSize: 12.5),
                      ),
                      Text(
                        _riskLabel(scan.riskLevel),
                        style: TextStyle(
                          color: riskColor,
                          fontSize: 22,
                          fontWeight: FontWeight.w800,
                        ),
                      ),
                      const SizedBox(height: 6),
                      Text(
                        '${scan.totalFindings} finding(s)',
                        style: TextStyle(color: c.muted),
                      ),
                      Text(
                        'Duration ${formatDuration(scan.startedAt, scan.finishedAt)}',
                        style: TextStyle(color: c.faint, fontSize: 12.5),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 10),
          ExpansionTile(
            tilePadding: EdgeInsets.zero,
            shape: const Border(),
            collapsedShape: const Border(),
            title: Text(
              'How is the score calculated?',
              style: TextStyle(color: c.muted, fontSize: 13.5),
            ),
            children: [
              Text(
                'Starts at 100. Each distinct rule deducts points by severity (critical 25, high 12, medium 5, low 2) multiplied by confidence. '
                'Repeats count once and observations are not scored. It is an indicator, not a guarantee of security.',
                style: TextStyle(color: c.muted, fontSize: 13, height: 1.4),
              ),
            ],
          ),
          const SectionTitle('Reports'),
          Row(
            children: [
              for (final f in const ['pdf', 'json', 'csv']) ...[
                Expanded(
                  child: OutlinedButton.icon(
                    onPressed: _downloading != null ? null : () => _download(f),
                    icon: _downloading == f
                        ? const SizedBox(
                            width: 16,
                            height: 16,
                            child: CircularProgressIndicator(strokeWidth: 2),
                          )
                        : const Icon(Icons.download, size: 18),
                    label: Text(f.toUpperCase()),
                  ),
                ),
                if (f != 'csv') const SizedBox(width: 8),
              ],
            ],
          ),
          SectionTitle(
            'Findings',
            trailing: SegmentedButton<bool>(
              showSelectedIcon: false,
              style: const ButtonStyle(visualDensity: VisualDensity.compact),
              segments: const [
                ButtonSegment(value: false, label: Text('Simple')),
                ButtonSegment(value: true, label: Text('Technical')),
              ],
              selected: {_technical},
              onSelectionChanged: (s) => setState(() => _technical = s.first),
            ),
          ),
          SizedBox(
            height: 42,
            child: ListView(
              scrollDirection: Axis.horizontal,
              children: [
                Padding(
                  padding: const EdgeInsets.only(right: 8),
                  child: ChoiceChip(
                    label: Text('All ${scan.findings.length}'),
                    selected: _severityFilter == null,
                    onSelected: (_) => setState(() => _severityFilter = null),
                  ),
                ),
                for (final k in severityOrder)
                  Padding(
                    padding: const EdgeInsets.only(right: 8),
                    child: ChoiceChip(
                      label: Text(
                        '${severityLabels[k]} ${scan.summary[k] ?? 0}',
                      ),
                      selected: _severityFilter == k,
                      onSelected: (_) => setState(
                        () => _severityFilter = _severityFilter == k ? null : k,
                      ),
                    ),
                  ),
              ],
            ),
          ),
          const SizedBox(height: 8),
          if (shown.isEmpty)
            const EmptyState(
              icon: Icons.shield_outlined,
              title: 'No findings',
              message:
                  'No checks reported a problem here. This does not prove the target is secure.',
            )
          else
            for (final f in shown)
              Padding(
                padding: const EdgeInsets.only(bottom: 10),
                child: _FindingCard(finding: f, technical: _technical),
              ),
          const SectionTitle('Engines'),
          for (final e in scan.engines)
            Padding(
              padding: const EdgeInsets.only(bottom: 8),
              child: AppCard(
                padding: const EdgeInsets.all(12),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Expanded(
                          child: Text(
                            e.name,
                            style: const TextStyle(fontWeight: FontWeight.w700),
                          ),
                        ),
                        Text(
                          e.status.replaceAll('_', ' '),
                          style: TextStyle(
                            color: e.status == 'completed' ? c.ok : c.warn,
                            fontWeight: FontWeight.w700,
                            fontSize: 12.5,
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 3),
                    Text(
                      e.detail,
                      style: TextStyle(color: c.muted, fontSize: 12.5),
                    ),
                  ],
                ),
              ),
            ),
          if (scan.notes.isNotEmpty) ...[
            const SectionTitle('Notes and limitations'),
            for (final n in scan.notes)
              Padding(
                padding: const EdgeInsets.only(bottom: 6),
                child: Text(
                  '- $n',
                  style: TextStyle(color: c.muted, fontSize: 13, height: 1.35),
                ),
              ),
          ],
        ],
      ),
    );
  }

  String _riskLabel(String? risk) => switch (risk) {
    'critical' => 'Critical risk',
    'high' => 'High risk',
    'medium' => 'Medium risk',
    'low' => 'Low risk',
    'minimal' => 'Minimal risk',
    _ => '-',
  };
}

class _FindingCard extends StatelessWidget {
  const _FindingCard({required this.finding, required this.technical});
  final Finding finding;
  final bool technical;

  @override
  Widget build(BuildContext context) {
    final c = AppColors.of(context);
    final f = finding;
    final color = AppColors.severity(f.severity);
    final radius = BorderRadius.circular(16);
    return Container(
      decoration: BoxDecoration(
        color: c.surface,
        borderRadius: radius,
        border: Border(
          left: BorderSide(color: color, width: 4),
          top: BorderSide(color: c.line),
          right: BorderSide(color: c.line),
          bottom: BorderSide(color: c.line),
        ),
      ),
      child: ClipRRect(
        borderRadius: radius,
        child: Theme(
          data: Theme.of(context).copyWith(dividerColor: Colors.transparent),
          child: ExpansionTile(
            tilePadding: const EdgeInsets.fromLTRB(14, 4, 10, 4),
            childrenPadding: const EdgeInsets.fromLTRB(14, 0, 14, 14),
            expandedCrossAxisAlignment: CrossAxisAlignment.start,
            title: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    SeverityChip(f.severity),
                    if (f.findingType == 'potential') ...[
                      const SizedBox(width: 6),
                      Text(
                        'Needs review',
                        style: TextStyle(
                          color: c.warn,
                          fontSize: 11.5,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                    ],
                  ],
                ),
                const SizedBox(height: 6),
                Text(
                  f.title,
                  style: const TextStyle(
                    fontWeight: FontWeight.w700,
                    fontSize: 14.5,
                    height: 1.25,
                  ),
                ),
              ],
            ),
            subtitle: Padding(
              padding: const EdgeInsets.only(top: 2),
              child: Text(
                f.location.isEmpty
                    ? f.category
                    : '${f.category} - ${f.location}',
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: TextStyle(color: c.faint, fontSize: 12),
              ),
            ),
            children: technical ? _technicalBody(c) : _simpleBody(c),
          ),
        ),
      ),
    );
  }

  Widget _h(String t, AppColors c) => Padding(
    padding: const EdgeInsets.only(top: 12, bottom: 4),
    child: Text(
      t.toUpperCase(),
      style: TextStyle(
        color: c.faint,
        fontSize: 11.5,
        fontWeight: FontWeight.w800,
        letterSpacing: 0.8,
      ),
    ),
  );

  Widget _evidence(AppColors c) => Container(
    width: double.infinity,
    padding: const EdgeInsets.all(10),
    decoration: BoxDecoration(
      color: c.bg,
      borderRadius: BorderRadius.circular(10),
      border: Border.all(color: c.line),
    ),
    child: SelectableText(
      finding.evidence,
      style: const TextStyle(
        fontFamily: 'monospace',
        fontSize: 12,
        height: 1.35,
      ),
    ),
  );

  List<Widget> _simpleBody(AppColors c) => [
    _h('What this means', c),
    Text(
      finding.simpleExplanation.isEmpty
          ? finding.description
          : finding.simpleExplanation,
      style: const TextStyle(height: 1.4),
    ),
    if (finding.whyItMatters.isNotEmpty) ...[
      _h('Why it matters', c),
      Text(finding.whyItMatters, style: const TextStyle(height: 1.4)),
    ],
    _h('How to fix it', c),
    Text(
      finding.remediation.isEmpty
          ? 'No remediation guidance available.'
          : finding.remediation,
      style: const TextStyle(height: 1.4),
    ),
    if (finding.evidence.isNotEmpty) ...[_h('Evidence', c), _evidence(c)],
  ];

  List<Widget> _technicalBody(AppColors c) {
    final rows = <MapEntry<String, String>>[
      MapEntry(
        'Type',
        findingTypeLabels[finding.findingType] ?? finding.findingType,
      ),
      MapEntry('Confidence', finding.confidence),
      MapEntry('Engine', finding.engine),
      if (finding.ruleId.isNotEmpty) MapEntry('Rule', finding.ruleId),
      if (finding.location.isNotEmpty)
        MapEntry(
          finding.url != null ? 'Affected URL' : 'Location',
          finding.location,
        ),
      if (finding.httpStatus != null)
        MapEntry('HTTP status', '${finding.httpStatus}'),
      if (finding.cwe != null && finding.cwe!.isNotEmpty)
        MapEntry('CWE', finding.cwe!),
      if (finding.cvssScore != null || finding.cvssVector != null)
        MapEntry(
          'CVSS',
          '${finding.cvssScore ?? ''} ${finding.cvssVector ?? ''}'.trim(),
        ),
    ];
    return [
      _h('Description', c),
      Text(
        finding.description.isEmpty
            ? finding.simpleExplanation
            : finding.description,
        style: const TextStyle(height: 1.4),
      ),
      const SizedBox(height: 8),
      for (final r in rows)
        Padding(
          padding: const EdgeInsets.symmetric(vertical: 3),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              SizedBox(
                width: 96,
                child: Text(
                  r.key,
                  style: TextStyle(color: c.muted, fontSize: 13),
                ),
              ),
              Expanded(
                child: SelectableText(
                  r.value,
                  style: const TextStyle(fontSize: 13),
                ),
              ),
            ],
          ),
        ),
      if (finding.evidence.isNotEmpty) ...[_h('Evidence', c), _evidence(c)],
      _h('Remediation', c),
      Text(finding.remediation, style: const TextStyle(height: 1.4)),
      if (finding.references.isNotEmpty) ...[
        _h('References', c),
        for (final r in finding.references)
          SelectableText(r, style: TextStyle(color: c.brand, fontSize: 12.5)),
      ],
    ];
  }
}
