const String kAppName = 'SecureScan AI';
const String kAppVersion = '1.0.0';

/// Optional build-time fallback address:
///   flutter build apk --release --dart-define=SCANNER_URL=https://scanner.example.com
/// The address entered inside the app always wins and is stored on the phone.
const String kDefaultServer = String.fromEnvironment(
  'SCANNER_URL',
  defaultValue: '',
);
