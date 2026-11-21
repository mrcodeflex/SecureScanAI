import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:securescan_ai/ui/theme.dart';
import 'package:securescan_ai/ui/widgets.dart';

Widget host(Widget child, {Brightness brightness = Brightness.dark}) {
  return MaterialApp(
    theme: buildTheme(brightness),
    home: Scaffold(body: Center(child: child)),
  );
}

void main() {
  testWidgets('SeverityChip shows the upper-case label', (tester) async {
    await tester.pumpWidget(host(const SeverityChip('high')));
    expect(find.text('HIGH'), findsOneWidget);
  });

  testWidgets('StatusBadge capitalises the status', (tester) async {
    await tester.pumpWidget(host(const StatusBadge('completed')));
    expect(find.text('Completed'), findsOneWidget);
  });

  testWidgets('ScoreRing shows the score, or a dash when unknown', (
    tester,
  ) async {
    await tester.pumpWidget(host(const ScoreRing(score: 82)));
    expect(find.text('82'), findsOneWidget);
    expect(find.text('out of 100'), findsOneWidget);

    await tester.pumpWidget(
      host(const ScoreRing(score: null), brightness: Brightness.light),
    );
    expect(find.text('-'), findsOneWidget);
  });

  testWidgets('SeverityDonut shows the total number of findings', (
    tester,
  ) async {
    await tester.pumpWidget(
      host(const SeverityDonut(counts: {'high': 2, 'low': 1})),
    );
    expect(find.text('3'), findsOneWidget);
    expect(find.text('findings'), findsOneWidget);
  });

  testWidgets('EmptyState shows title, message and action', (tester) async {
    await tester.pumpWidget(
      host(
        const EmptyState(
          icon: Icons.shield_outlined,
          title: 'No findings',
          message: 'Nothing to show',
          action: Text('Retry'),
        ),
      ),
    );
    expect(find.text('No findings'), findsOneWidget);
    expect(find.text('Nothing to show'), findsOneWidget);
    expect(find.text('Retry'), findsOneWidget);
  });
}
