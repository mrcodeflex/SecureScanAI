import 'package:flutter/material.dart';

/// Brand palette shared with the web interface.
class AppColors {
  const AppColors({
    required this.bg,
    required this.surface,
    required this.surface2,
    required this.line,
    required this.text,
    required this.muted,
    required this.faint,
    required this.brand,
    required this.ok,
    required this.bad,
    required this.warn,
  });

  final Color bg;
  final Color surface;
  final Color surface2;
  final Color line;
  final Color text;
  final Color muted;
  final Color faint;
  final Color brand;
  final Color ok;
  final Color bad;
  final Color warn;

  static const AppColors dark = AppColors(
    bg: Color(0xFF0A1020),
    surface: Color(0xFF111B35),
    surface2: Color(0xFF16233F),
    line: Color(0xFF223056),
    text: Color(0xFFE8EEFC),
    muted: Color(0xFF93A3C7),
    faint: Color(0xFF62739A),
    brand: Color(0xFF4B8FFF),
    ok: Color(0xFF34D399),
    bad: Color(0xFFF87171),
    warn: Color(0xFFFBBF24),
  );

  static const AppColors light = AppColors(
    bg: Color(0xFFF3F6FC),
    surface: Color(0xFFFFFFFF),
    surface2: Color(0xFFF6F8FD),
    line: Color(0xFFDDE4F2),
    text: Color(0xFF0E1A33),
    muted: Color(0xFF53638A),
    faint: Color(0xFF7E8CAE),
    brand: Color(0xFF2563EB),
    ok: Color(0xFF059669),
    bad: Color(0xFFDC2626),
    warn: Color(0xFFB45309),
  );

  static AppColors of(BuildContext context) =>
      Theme.of(context).brightness == Brightness.dark ? dark : light;

  static Color severity(String s) {
    switch (s) {
      case 'critical':
        return const Color(0xFFEF4444);
      case 'high':
        return const Color(0xFFF97316);
      case 'medium':
        return const Color(0xFFEAB308);
      case 'low':
        return const Color(0xFF3B82F6);
      default:
        return const Color(0xFF94A3B8);
    }
  }

  static Color score(int? score, AppColors c) {
    if (score == null) return c.faint;
    if (score >= 80) return c.ok;
    if (score >= 50) return const Color(0xFFEAB308);
    return const Color(0xFFEF4444);
  }
}

ThemeData buildTheme(Brightness brightness) {
  final c = brightness == Brightness.dark ? AppColors.dark : AppColors.light;
  final scheme =
      ColorScheme.fromSeed(seedColor: c.brand, brightness: brightness).copyWith(
        primary: c.brand,
        surface: c.surface,
        onSurface: c.text,
        error: c.bad,
      );
  return ThemeData(
    useMaterial3: true,
    brightness: brightness,
    colorScheme: scheme,
    scaffoldBackgroundColor: c.bg,
    dividerColor: c.line,
    visualDensity: VisualDensity.standard,
  );
}
