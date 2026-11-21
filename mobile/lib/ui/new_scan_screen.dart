import 'package:file_selector/file_selector.dart';
import 'package:flutter/material.dart';

import '../core/api_client.dart';
import '../core/app_state.dart';
import '../core/format.dart';
import '../core/models.dart';
import 'scan_detail_screen.dart';
import 'theme.dart';
import 'widgets.dart';

class NewScanScreen extends StatefulWidget {
  const NewScanScreen({super.key});

  @override
  State<NewScanScreen> createState() => _NewScanScreenState();
}

class _NewScanScreenState extends State<NewScanScreen> {
  final TextEditingController _url = TextEditingController();
  String _kind = 'website';
  String _mode = 'beginner';
  bool _authorized = false;
  bool _active = false;
  bool _busy = false;
  String? _error;
  XFile? _file;
  int _fileSize = 0;
  List<CheckOption> _checks = const [];
  List<EngineInfo> _engines = const [];
  final Set<String> _selectedChecks = {};
  final Set<String> _selectedEngines = {};
  bool _optionsLoaded = false;

  @override
  void dispose() {
    _url.dispose();
    super.dispose();
  }

  Future<void> _loadOptions() async {
    if (_optionsLoaded) return;
    _optionsLoaded = true;
    try {
      final api = AppScope.of(context).api;
      final checks = await api.checks();
      final engines = await api.engines();
      if (!mounted) return;
      setState(() {
        _checks = checks;
        _engines = engines
            .where((e) => e.id == 'semgrep' || e.id == 'trivy' || e.id == 'osv')
            .toList();
        _selectedChecks
          ..clear()
          ..addAll(checks.where((c) => c.kind == 'passive').map((c) => c.id));
        _selectedEngines
          ..clear()
          ..addAll(
            _engines
                .where((e) => e.state == 'installed' || e.state == 'available')
                .map((e) => e.id),
          );
      });
    } on ApiException catch (e) {
      _optionsLoaded = false;
      if (mounted) setState(() => _error = e.message);
    }
  }

  Future<void> _pickFile() async {
    const zipType = XTypeGroup(
      label: 'ZIP archive',
      extensions: ['zip'],
      mimeTypes: ['application/zip', 'application/x-zip-compressed'],
    );
    final picked = await openFile(acceptedTypeGroups: [zipType]);
    if (picked == null) return;
    final size = await picked.length();
    if (!mounted) return;
    setState(() {
      _file = picked;
      _fileSize = size;
      _error = null;
    });
  }

  Future<void> _start() async {
    final api = AppScope.of(context).api;
    final nav = Navigator.of(context);
    setState(() => _error = null);
    if (_kind == 'website') {
      if (_url.text.trim().isEmpty) {
        setState(() => _error = 'Enter the website address to scan.');
        return;
      }
      if (!_authorized) {
        setState(
          () =>
              _error = 'Confirm that you are authorized to scan this website.',
        );
        return;
      }
    } else {
      if (_file == null) {
        setState(() => _error = 'Choose a .zip file to scan.');
        return;
      }
      if (!_authorized) {
        setState(
          () => _error = 'Confirm that you are authorized to assess this code.',
        );
        return;
      }
    }
    setState(() => _busy = true);
    try {
      final Scan scan;
      if (_kind == 'website') {
        scan = await api.startWebsiteScan(
          url: _url.text.trim(),
          mode: _mode,
          checks: _mode == 'advanced' ? _selectedChecks.toList() : null,
          activeChecks: _mode == 'advanced' && _active,
        );
      } else {
        scan = await api.startSourceScan(
          file: _file!,
          mode: _mode,
          engines: _mode == 'advanced' ? _selectedEngines.toList() : const [],
        );
      }
      if (!mounted) return;
      setState(() {
        _url.clear();
        _file = null;
        _authorized = false;
      });
      await nav.push(
        MaterialPageRoute<void>(
          builder: (_) => ScanDetailScreen(scanId: scan.id),
        ),
      );
    } on ApiException catch (e) {
      if (mounted) setState(() => _error = e.message);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final c = AppColors.of(context);
    if (_mode == 'advanced') _loadOptions();
    return ListView(
      padding: const EdgeInsets.fromLTRB(16, 14, 16, 28),
      children: [
        const Text(
          'New scan',
          style: TextStyle(
            fontSize: 26,
            fontWeight: FontWeight.w800,
            letterSpacing: -0.5,
          ),
        ),
        Text(
          'Choose what to assess, then how much detail you want.',
          style: TextStyle(color: c.muted),
        ),
        const SizedBox(height: 16),
        SegmentedButton<String>(
          segments: const [
            ButtonSegment(
              value: 'website',
              icon: Icon(Icons.public),
              label: Text('Website'),
            ),
            ButtonSegment(
              value: 'source',
              icon: Icon(Icons.code),
              label: Text('Source code'),
            ),
          ],
          selected: {_kind},
          onSelectionChanged: (s) => setState(() {
            _kind = s.first;
            _error = null;
            _authorized = false;
          }),
        ),
        const SizedBox(height: 16),
        Row(
          children: [
            Expanded(
              child: _ModeCard(
                'Beginner',
                'Enter an address and get a plain-language report.',
                Icons.visibility_outlined,
                _mode == 'beginner',
                () => setState(() => _mode = 'beginner'),
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: _ModeCard(
                'Advanced',
                'Pick checks and engines; see technical detail.',
                Icons.tune,
                _mode == 'advanced',
                () => setState(() => _mode = 'advanced'),
              ),
            ),
          ],
        ),
        const SizedBox(height: 18),
        if (_kind == 'website') ..._websiteForm(c) else ..._sourceForm(c),
        const SizedBox(height: 8),
        CheckboxListTile(
          value: _authorized,
          onChanged: (v) => setState(() => _authorized = v ?? false),
          controlAffinity: ListTileControlAffinity.leading,
          contentPadding: EdgeInsets.zero,
          title: Text(
            _kind == 'website'
                ? 'I am authorized to scan this website'
                : 'I own this code or am authorized to assess it',
            style: const TextStyle(fontWeight: FontWeight.w700, fontSize: 14),
          ),
          subtitle: Text(
            _kind == 'website'
                ? 'I own it or have written permission. Scans are recorded in the audit log.'
                : 'The archive is read as text and deleted afterwards. Nothing is executed.',
            style: TextStyle(color: c.muted, fontSize: 12.5),
          ),
        ),
        if (_error != null) ...[
          const SizedBox(height: 8),
          Banner2(_error!, error: true, icon: Icons.error_outline),
        ],
        const SizedBox(height: 14),
        SizedBox(
          height: 52,
          child: FilledButton.icon(
            onPressed: _busy ? null : _start,
            icon: _busy
                ? const SizedBox(
                    width: 18,
                    height: 18,
                    child: CircularProgressIndicator(strokeWidth: 2.5),
                  )
                : const Icon(Icons.bolt),
            label: Text(
              _busy
                  ? (_kind == 'source' ? 'Uploading...' : 'Starting...')
                  : 'Start scan',
              style: const TextStyle(fontSize: 16, fontWeight: FontWeight.w700),
            ),
          ),
        ),
      ],
    );
  }

  List<Widget> _websiteForm(AppColors c) {
    final passive = _checks.where((x) => x.kind == 'passive').toList();
    final active = _checks.where((x) => x.kind == 'active').toList();
    return [
      TextField(
        controller: _url,
        keyboardType: TextInputType.url,
        autocorrect: false,
        enableSuggestions: false,
        decoration: InputDecoration(
          labelText: 'Website address',
          hintText: 'https://example.com',
          helperText:
              'Public http(s) addresses only. Private and local addresses are blocked.',
          helperMaxLines: 2,
          prefixIcon: const Icon(Icons.public),
          border: OutlineInputBorder(borderRadius: BorderRadius.circular(14)),
        ),
      ),
      if (_mode == 'advanced') ...[
        const SectionTitle('Passive checks'),
        if (_checks.isEmpty)
          const Padding(
            padding: EdgeInsets.all(12),
            child: Center(child: CircularProgressIndicator()),
          ),
        for (final ch in passive) _checkTile(ch, c),
        if (active.isNotEmpty) ...[
          const SectionTitle('Active checks (authorized targets only)'),
          const Banner2(
            'Active checks send a few harmless probe requests. They only run for hosts on the server\'s authorization allowlist; otherwise the server refuses the scan.',
            icon: Icons.warning_amber_outlined,
          ),
          SwitchListTile(
            value: _active,
            onChanged: (v) => setState(() => _active = v),
            contentPadding: EdgeInsets.zero,
            title: const Text(
              'Enable active checks',
              style: TextStyle(fontWeight: FontWeight.w700),
            ),
          ),
          if (_active)
            for (final ch in active) _checkTile(ch, c),
        ],
      ],
    ];
  }

  Widget _checkTile(CheckOption ch, AppColors c) => CheckboxListTile(
    value: _selectedChecks.contains(ch.id),
    onChanged: (v) => setState(
      () => v == true
          ? _selectedChecks.add(ch.id)
          : _selectedChecks.remove(ch.id),
    ),
    controlAffinity: ListTileControlAffinity.leading,
    contentPadding: EdgeInsets.zero,
    dense: true,
    title: Text(ch.label, style: const TextStyle(fontWeight: FontWeight.w700)),
    subtitle: Text(
      ch.description,
      style: TextStyle(color: c.muted, fontSize: 12),
    ),
  );

  List<Widget> _sourceForm(AppColors c) => [
    AppCard(
      onTap: _pickFile,
      padding: const EdgeInsets.symmetric(vertical: 28, horizontal: 16),
      child: Column(
        children: [
          Icon(
            _file == null ? Icons.upload_file : Icons.folder_zip_outlined,
            size: 40,
            color: c.brand,
          ),
          const SizedBox(height: 10),
          Text(
            _file == null ? 'Choose a .zip file' : _file!.name,
            textAlign: TextAlign.center,
            style: const TextStyle(fontWeight: FontWeight.w800, fontSize: 15),
          ),
          const SizedBox(height: 4),
          Text(
            _file == null
                ? 'Source code is read, never executed.'
                : formatBytes(_fileSize),
            style: TextStyle(color: c.muted, fontSize: 13),
          ),
        ],
      ),
    ),
    if (_mode == 'advanced') ...[
      const SectionTitle('Scan engines'),
      const Banner2(
        'The built-in rules always run. Optional engines run only if they are installed on the server.',
      ),
      const SizedBox(height: 6),
      if (_engines.isEmpty)
        const Padding(
          padding: EdgeInsets.all(12),
          child: Center(child: CircularProgressIndicator()),
        ),
      for (final e in _engines)
        CheckboxListTile(
          value: _selectedEngines.contains(e.id),
          onChanged: (e.state == 'installed' || e.state == 'available')
              ? (v) => setState(
                  () => v == true
                      ? _selectedEngines.add(e.id)
                      : _selectedEngines.remove(e.id),
                )
              : null,
          controlAffinity: ListTileControlAffinity.leading,
          contentPadding: EdgeInsets.zero,
          dense: true,
          title: Text(
            e.name,
            style: const TextStyle(fontWeight: FontWeight.w700),
          ),
          subtitle: Text(
            (e.state == 'installed' || e.state == 'available')
                ? e.detail
                : 'Not installed - scan not performed',
            style: TextStyle(color: c.muted, fontSize: 12),
          ),
        ),
    ],
  ];
}

class _ModeCard extends StatelessWidget {
  const _ModeCard(this.title, this.text, this.icon, this.selected, this.onTap);
  final String title;
  final String text;
  final IconData icon;
  final bool selected;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final c = AppColors.of(context);
    return Material(
      color: selected ? c.brand.withValues(alpha: 0.14) : c.surface,
      borderRadius: BorderRadius.circular(16),
      child: InkWell(
        borderRadius: BorderRadius.circular(16),
        onTap: onTap,
        child: Container(
          padding: const EdgeInsets.all(14),
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(16),
            border: Border.all(
              color: selected ? c.brand : c.line,
              width: selected ? 1.6 : 1,
            ),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Icon(icon, color: c.brand),
              const SizedBox(height: 8),
              Text(
                title,
                style: const TextStyle(
                  fontWeight: FontWeight.w800,
                  fontSize: 15,
                ),
              ),
              const SizedBox(height: 2),
              Text(
                text,
                style: TextStyle(color: c.muted, fontSize: 12.5, height: 1.3),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
