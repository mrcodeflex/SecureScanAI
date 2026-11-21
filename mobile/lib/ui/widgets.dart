import 'dart:math' as math;

import 'package:flutter/material.dart';

import '../core/models.dart';
import 'theme.dart';

void showMessage(BuildContext context, String message, {bool error = false}) {
  final c = AppColors.of(context);
  ScaffoldMessenger.of(context)
    ..hideCurrentSnackBar()
    ..showSnackBar(
      SnackBar(
        content: Text(message),
        behavior: SnackBarBehavior.floating,
        backgroundColor: error ? c.bad : c.surface2,
        duration: Duration(seconds: error ? 6 : 3),
      ),
    );
}

class AppCard extends StatelessWidget {
  const AppCard({
    super.key,
    required this.child,
    this.padding = const EdgeInsets.all(16),
    this.onTap,
    this.accent,
  });

  final Widget child;
  final EdgeInsetsGeometry padding;
  final VoidCallback? onTap;
  final Color? accent;

  @override
  Widget build(BuildContext context) {
    final c = AppColors.of(context);
    final radius = BorderRadius.circular(16);
    return Material(
      color: c.surface,
      borderRadius: radius,
      child: InkWell(
        borderRadius: radius,
        onTap: onTap,
        child: Container(
          padding: padding,
          decoration: BoxDecoration(
            borderRadius: radius,
            border: Border.all(color: c.line),
            gradient: accent == null
                ? null
                : LinearGradient(
                    colors: [
                      accent!.withValues(alpha: 0.16),
                      Colors.transparent,
                    ],
                    stops: const [0, 0.55],
                  ),
          ),
          child: child,
        ),
      ),
    );
  }
}

class SeverityChip extends StatelessWidget {
  const SeverityChip(this.severity, {super.key});
  final String severity;

  @override
  Widget build(BuildContext context) {
    final color = AppColors.severity(severity);
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 9, vertical: 3),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.16),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Container(
            width: 7,
            height: 7,
            decoration: BoxDecoration(color: color, shape: BoxShape.circle),
          ),
          const SizedBox(width: 6),
          Text(
            (severityLabels[severity] ?? severity).toUpperCase(),
            style: TextStyle(
              color: color,
              fontSize: 11,
              fontWeight: FontWeight.w800,
              letterSpacing: 0.5,
            ),
          ),
        ],
      ),
    );
  }
}

class StatusBadge extends StatelessWidget {
  const StatusBadge(this.status, {super.key});
  final String status;

  @override
  Widget build(BuildContext context) {
    final c = AppColors.of(context);
    final color = switch (status) {
      'completed' => c.ok,
      'failed' => c.bad,
      'cancelled' => c.warn,
      _ => c.brand,
    };
    final label = status.isEmpty
        ? ''
        : status[0].toUpperCase() + status.substring(1);
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 3),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.15),
        borderRadius: BorderRadius.circular(99),
      ),
      child: Text(
        label,
        style: TextStyle(
          color: color,
          fontSize: 12,
          fontWeight: FontWeight.w700,
        ),
      ),
    );
  }
}

class SectionTitle extends StatelessWidget {
  const SectionTitle(this.text, {super.key, this.trailing});
  final String text;
  final Widget? trailing;

  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.only(top: 8, bottom: 10),
    child: Row(
      children: [
        Expanded(
          child: Text(
            text,
            style: const TextStyle(fontSize: 16, fontWeight: FontWeight.w800),
          ),
        ),
        if (trailing != null) trailing!,
      ],
    ),
  );
}

class EmptyState extends StatelessWidget {
  const EmptyState({
    super.key,
    required this.icon,
    required this.title,
    this.message = '',
    this.action,
  });
  final IconData icon;
  final String title;
  final String message;
  final Widget? action;

  @override
  Widget build(BuildContext context) {
    final c = AppColors.of(context);
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(28),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(icon, size: 44, color: c.faint),
            const SizedBox(height: 12),
            Text(
              title,
              textAlign: TextAlign.center,
              style: const TextStyle(fontSize: 17, fontWeight: FontWeight.w800),
            ),
            if (message.isNotEmpty) ...[
              const SizedBox(height: 6),
              Text(
                message,
                textAlign: TextAlign.center,
                style: TextStyle(color: c.muted),
              ),
            ],
            if (action != null) ...[const SizedBox(height: 16), action!],
          ],
        ),
      ),
    );
  }
}

class ErrorView extends StatelessWidget {
  const ErrorView({super.key, required this.message, required this.onRetry});
  final String message;
  final VoidCallback onRetry;

  @override
  Widget build(BuildContext context) => EmptyState(
    icon: Icons.cloud_off_outlined,
    title: 'Something went wrong',
    message: message,
    action: FilledButton.icon(
      onPressed: onRetry,
      icon: const Icon(Icons.refresh),
      label: const Text('Retry'),
    ),
  );
}

class Loading extends StatelessWidget {
  const Loading({super.key});
  @override
  Widget build(BuildContext context) => const Center(
    child: Padding(
      padding: EdgeInsets.all(40),
      child: CircularProgressIndicator(),
    ),
  );
}

class Banner2 extends StatelessWidget {
  const Banner2(
    this.text, {
    super.key,
    this.error = false,
    this.icon = Icons.info_outline,
  });
  final String text;
  final bool error;
  final IconData icon;

  @override
  Widget build(BuildContext context) {
    final c = AppColors.of(context);
    final color = error ? c.bad : c.brand;
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: color.withValues(alpha: 0.45)),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(icon, size: 18, color: color),
          const SizedBox(width: 10),
          Expanded(
            child: Text(
              text,
              style: const TextStyle(fontSize: 13, height: 1.35),
            ),
          ),
        ],
      ),
    );
  }
}

/// SecureScan AI shield-and-radar mark.
class BrandMark extends StatelessWidget {
  const BrandMark({super.key, this.size = 72});
  final double size;
  @override
  Widget build(BuildContext context) =>
      CustomPaint(size: Size(size, size), painter: _MarkPainter());
}

class _MarkPainter extends CustomPainter {
  @override
  void paint(Canvas canvas, Size s) {
    final w = s.width / 48, h = s.height / 48;
    final shield = Path()
      ..moveTo(24 * w, 3 * h)
      ..lineTo(41 * w, 9.4 * h)
      ..lineTo(41 * w, 21.7 * h)
      ..cubicTo(41 * w, 32.1 * h, 34 * w, 40.3 * h, 24 * w, 45 * h)
      ..cubicTo(14 * w, 40.3 * h, 7 * w, 32.1 * h, 7 * w, 21.7 * h)
      ..lineTo(7 * w, 9.4 * h)
      ..close();
    canvas.drawPath(
      shield,
      Paint()
        ..shader = const LinearGradient(
          colors: [Color(0xFF4F9BFF), Color(0xFF1D4ED8)],
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
        ).createShader(Offset.zero & s),
    );
    final ring = Paint()
      ..color = Colors.white
      ..style = PaintingStyle.stroke
      ..strokeWidth = 2.6 * w;
    canvas.drawCircle(Offset(24 * w, 23 * h), 8.5 * w, ring);
    canvas.drawLine(
      Offset(24 * w, 23 * h),
      Offset(30 * w, 17 * h),
      Paint()
        ..color = const Color(0xFF22D3EE)
        ..strokeWidth = 2.8 * w
        ..strokeCap = StrokeCap.round,
    );
    canvas.drawCircle(
      Offset(24 * w, 23 * h),
      2 * w,
      Paint()..color = Colors.white,
    );
  }

  @override
  bool shouldRepaint(covariant CustomPainter oldDelegate) => false;
}

class ScoreRing extends StatelessWidget {
  const ScoreRing({super.key, required this.score, this.size = 120});
  final int? score;
  final double size;

  @override
  Widget build(BuildContext context) {
    final c = AppColors.of(context);
    final color = AppColors.score(score, c);
    return SizedBox(
      width: size,
      height: size,
      child: CustomPaint(
        painter: _RingPainter((score ?? 0) / 100, color, c.line),
        child: Center(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(
                score == null ? '-' : '$score',
                style: TextStyle(
                  fontSize: size * 0.3,
                  fontWeight: FontWeight.w800,
                  height: 1,
                ),
              ),
              Text(
                'out of 100',
                style: TextStyle(fontSize: size * 0.085, color: c.muted),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _RingPainter extends CustomPainter {
  _RingPainter(this.fraction, this.color, this.track);
  final double fraction;
  final Color color;
  final Color track;

  @override
  void paint(Canvas canvas, Size s) {
    final stroke = s.width * 0.09;
    final rect = Rect.fromCircle(
      center: s.center(Offset.zero),
      radius: s.width / 2 - stroke / 2,
    );
    canvas.drawArc(
      rect,
      0,
      math.pi * 2,
      false,
      Paint()
        ..color = track
        ..style = PaintingStyle.stroke
        ..strokeWidth = stroke,
    );
    canvas.drawArc(
      rect,
      -math.pi / 2,
      math.pi * 2 * fraction.clamp(0, 1),
      false,
      Paint()
        ..color = color
        ..style = PaintingStyle.stroke
        ..strokeWidth = stroke
        ..strokeCap = StrokeCap.round,
    );
  }

  @override
  bool shouldRepaint(covariant _RingPainter old) =>
      old.fraction != fraction || old.color != color || old.track != track;
}

class SeverityDonut extends StatelessWidget {
  const SeverityDonut({super.key, required this.counts, this.size = 150});
  final Map<String, int> counts;
  final double size;

  @override
  Widget build(BuildContext context) {
    final c = AppColors.of(context);
    final total = severityOrder.fold<int>(0, (a, k) => a + (counts[k] ?? 0));
    return SizedBox(
      width: size,
      height: size,
      child: CustomPaint(
        painter: _DonutPainter(counts, c.line),
        child: Center(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(
                '$total',
                style: TextStyle(
                  fontSize: size * 0.22,
                  fontWeight: FontWeight.w800,
                  height: 1,
                ),
              ),
              Text(
                'findings',
                style: TextStyle(fontSize: size * 0.08, color: c.muted),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _DonutPainter extends CustomPainter {
  _DonutPainter(this.counts, this.track);
  final Map<String, int> counts;
  final Color track;

  @override
  void paint(Canvas canvas, Size s) {
    final stroke = s.width * 0.13;
    final rect = Rect.fromCircle(
      center: s.center(Offset.zero),
      radius: s.width / 2 - stroke / 2,
    );
    canvas.drawArc(
      rect,
      0,
      math.pi * 2,
      false,
      Paint()
        ..color = track
        ..style = PaintingStyle.stroke
        ..strokeWidth = stroke,
    );
    final total = severityOrder.fold<int>(0, (a, k) => a + (counts[k] ?? 0));
    if (total == 0) return;
    var start = -math.pi / 2;
    for (final k in severityOrder) {
      final n = counts[k] ?? 0;
      if (n == 0) continue;
      final sweep = math.pi * 2 * n / total;
      canvas.drawArc(
        rect,
        start,
        math.max(0.02, sweep - 0.03),
        false,
        Paint()
          ..color = AppColors.severity(k)
          ..style = PaintingStyle.stroke
          ..strokeWidth = stroke,
      );
      start += sweep;
    }
  }

  @override
  bool shouldRepaint(covariant _DonutPainter old) => old.counts != counts;
}

/// Small helper used by list rows.
class ScanRow extends StatelessWidget {
  const ScanRow({
    super.key,
    required this.scan,
    required this.onTap,
    required this.subtitle,
  });
  final Scan scan;
  final VoidCallback onTap;
  final String subtitle;

  @override
  Widget build(BuildContext context) {
    final c = AppColors.of(context);
    return AppCard(
      onTap: onTap,
      padding: const EdgeInsets.all(14),
      child: Row(
        children: [
          Container(
            width: 42,
            height: 42,
            decoration: BoxDecoration(
              color: c.brand.withValues(alpha: 0.14),
              borderRadius: BorderRadius.circular(12),
            ),
            child: Icon(
              scan.isWebsite ? Icons.public : Icons.code,
              color: c.brand,
              size: 22,
            ),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  scan.title,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: const TextStyle(
                    fontWeight: FontWeight.w700,
                    fontSize: 15,
                  ),
                ),
                const SizedBox(height: 3),
                Text(
                  subtitle,
                  style: TextStyle(color: c.muted, fontSize: 12.5),
                ),
              ],
            ),
          ),
          const SizedBox(width: 8),
          Column(
            crossAxisAlignment: CrossAxisAlignment.end,
            children: [
              StatusBadge(scan.status),
              const SizedBox(height: 5),
              if (scan.isRunning)
                Text(
                  '${scan.progress}%',
                  style: TextStyle(color: c.muted, fontSize: 12),
                )
              else if (scan.score != null)
                Text(
                  '${scan.score}',
                  style: TextStyle(
                    color: AppColors.score(scan.score, c),
                    fontWeight: FontWeight.w800,
                    fontSize: 16,
                  ),
                ),
            ],
          ),
        ],
      ),
    );
  }
}
