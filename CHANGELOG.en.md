# Changelog

## 1.0.1

- First FinchGate release: personal edition of the connector, renamed and rebranded.
- App version set to 1.0.1.
- Fixed Rust formatting in tray.rs so the CI format gate passes.
- Fixed the logs page clock map missing the Persian locale, which broke the TypeScript build.
- Regenerated the app icons as RGBA; the tray icon loader rejects RGB PNGs.
- The packaged exe and build artifact are now named FinchGate (FinchGate.exe / finchgate-exe).
