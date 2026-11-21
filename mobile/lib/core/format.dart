/// Small formatting helpers (no intl dependency).
String two(int n) => n.toString().padLeft(2, '0');

String formatDateTime(DateTime? d) {
  if (d == null) return '-';
  final l = d.toLocal();
  const months = [
    'Jan',
    'Feb',
    'Mar',
    'Apr',
    'May',
    'Jun',
    'Jul',
    'Aug',
    'Sep',
    'Oct',
    'Nov',
    'Dec',
  ];
  return '${l.day} ${months[l.month - 1]} ${l.year}, ${two(l.hour)}:${two(l.minute)}';
}

String timeAgo(DateTime? d, {DateTime? now}) {
  if (d == null) return '-';
  final diff = (now ?? DateTime.now()).difference(d.toLocal());
  if (diff.inSeconds < 45) return 'just now';
  if (diff.inMinutes < 60) return '${diff.inMinutes} min ago';
  if (diff.inHours < 24) return '${diff.inHours} h ago';
  if (diff.inDays < 7) return '${diff.inDays} d ago';
  return formatDateTime(d);
}

String formatBytes(int bytes) {
  if (bytes >= 1024 * 1024) {
    return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
  }
  final kb = (bytes / 1024).ceil();
  return '${kb < 1 ? 1 : kb} KB';
}

String formatDuration(DateTime? start, DateTime? end) {
  if (start == null) return '-';
  final raw = (end ?? DateTime.now().toUtc()).difference(start).inSeconds;
  final s = raw < 0 ? 0 : raw;
  return s < 60 ? '$s s' : '${s ~/ 60} min ${s % 60} s';
}
