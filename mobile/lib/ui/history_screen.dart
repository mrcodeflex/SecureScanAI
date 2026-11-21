import 'dart:async';

import 'package:flutter/material.dart';

import '../core/api_client.dart';
import '../core/app_state.dart';
import '../core/format.dart';
import '../core/models.dart';
import 'scan_detail_screen.dart';
import 'widgets.dart';

class HistoryScreen extends StatefulWidget {
  const HistoryScreen({super.key, required this.active});
  final bool active;

  @override
  State<HistoryScreen> createState() => _HistoryScreenState();
}

class _HistoryScreenState extends State<HistoryScreen> {
  static const int _pageSize = 20;
  final TextEditingController _search = TextEditingController();
  final List<Scan> _items = [];
  int _total = 0;
  String _status = '';
  String? _error;
  bool _loading = true;
  bool _loadingMore = false;
  Timer? _debounce;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _load());
  }

  @override
  void didUpdateWidget(covariant HistoryScreen old) {
    super.didUpdateWidget(old);
    if (widget.active && !old.active) _load(silent: true);
  }

  @override
  void dispose() {
    _debounce?.cancel();
    _search.dispose();
    super.dispose();
  }

  Future<void> _load({bool silent = false}) async {
    if (!silent) setState(() => _loading = true);
    try {
      final r = await AppScope.of(context).api.listScans(
        status: _status,
        query: _search.text.trim(),
        limit: _pageSize,
      );
      if (!mounted) return;
      setState(() {
        _items
          ..clear()
          ..addAll(r.items);
        _total = r.total;
        _error = null;
        _loading = false;
      });
    } on ApiException catch (e) {
      if (mounted) {
        setState(() {
          _error = e.message;
          _loading = false;
        });
      }
    }
  }

  Future<void> _more() async {
    if (_loadingMore || _items.length >= _total) return;
    setState(() => _loadingMore = true);
    try {
      final r = await AppScope.of(context).api.listScans(
        status: _status,
        query: _search.text.trim(),
        offset: _items.length,
        limit: _pageSize,
      );
      if (mounted) setState(() => _items.addAll(r.items));
    } on ApiException catch (e) {
      if (mounted) showMessage(context, e.message, error: true);
    } finally {
      if (mounted) setState(() => _loadingMore = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final filters = const {
      '': 'All',
      'completed': 'Completed',
      'running': 'Running',
      'failed': 'Failed',
      'cancelled': 'Cancelled',
    };
    return Column(
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 14, 16, 4),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text(
                'Scan history',
                style: TextStyle(
                  fontSize: 26,
                  fontWeight: FontWeight.w800,
                  letterSpacing: -0.5,
                ),
              ),
              const SizedBox(height: 12),
              TextField(
                controller: _search,
                textInputAction: TextInputAction.search,
                onChanged: (_) {
                  _debounce?.cancel();
                  _debounce = Timer(const Duration(milliseconds: 350), _load);
                },
                decoration: InputDecoration(
                  hintText: 'Search by target',
                  prefixIcon: const Icon(Icons.search),
                  isDense: true,
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(14),
                  ),
                ),
              ),
              const SizedBox(height: 10),
              SizedBox(
                height: 40,
                child: ListView(
                  scrollDirection: Axis.horizontal,
                  children: [
                    for (final e in filters.entries)
                      Padding(
                        padding: const EdgeInsets.only(right: 8),
                        child: ChoiceChip(
                          label: Text(e.value),
                          selected: _status == e.key,
                          onSelected: (_) {
                            setState(() => _status = e.key);
                            _load();
                          },
                        ),
                      ),
                  ],
                ),
              ),
            ],
          ),
        ),
        Expanded(child: _content()),
      ],
    );
  }

  Widget _content() {
    if (_loading) return const Loading();
    if (_error != null && _items.isEmpty) {
      return ErrorView(message: _error!, onRetry: _load);
    }
    return RefreshIndicator(
      onRefresh: () => _load(silent: true),
      child: _items.isEmpty
          ? ListView(
              children: const [
                SizedBox(height: 60),
                EmptyState(
                  icon: Icons.history,
                  title: 'No scans found',
                  message: 'Scans you run will appear here.',
                ),
              ],
            )
          : ListView.builder(
              physics: const AlwaysScrollableScrollPhysics(),
              padding: const EdgeInsets.fromLTRB(16, 8, 16, 24),
              itemCount: _items.length + 1,
              itemBuilder: (context, i) {
                if (i == _items.length) {
                  if (_items.length >= _total) {
                    return Padding(
                      padding: const EdgeInsets.all(12),
                      child: Center(
                        child: Text(
                          '$_total scan(s)',
                          style: const TextStyle(fontSize: 12),
                        ),
                      ),
                    );
                  }
                  return Padding(
                    padding: const EdgeInsets.all(8),
                    child: Center(
                      child: _loadingMore
                          ? const CircularProgressIndicator()
                          : OutlinedButton(
                              onPressed: _more,
                              child: const Text('Load more'),
                            ),
                    ),
                  );
                }
                final s = _items[i];
                final findings = s.summary['total'];
                return Padding(
                  padding: const EdgeInsets.only(bottom: 10),
                  child: ScanRow(
                    scan: s,
                    subtitle:
                        '${s.isWebsite ? 'Website' : 'Source ZIP'}${findings != null && s.isCompleted ? ' - $findings finding(s)' : ''} - ${timeAgo(s.createdAt)}',
                    onTap: () => Navigator.of(context).push(
                      MaterialPageRoute<void>(
                        builder: (_) => ScanDetailScreen(scanId: s.id),
                      ),
                    ),
                  ),
                );
              },
            ),
    );
  }
}
