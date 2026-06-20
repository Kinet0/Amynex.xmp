# Amynex.xmp

Amynex.xmp is an advanced, privacy-first Chrome extension for real-time phishing detection. It performs local URL intelligence, DOM inspection, content analysis, reputation matching, risk scoring, and secure reporting.

## Tip
- make a shortcut command for Amynex.xmp, it makes your life easier.
- i literallty made this just because i dont want to open another tab when im browsing sketch websites. peace

## Project Features

- URL intelligence with lookalike, punycode, multiple subdomains, IP addresses, and entropy analysis.
- DOM threat analysis for password fields, credential collection forms, external form actions, hidden inputs, suspicious redirects, and JavaScript behavior.
- Content analysis for phishing language, social engineering cues, and brand impersonation.
- Local threat intelligence engine with phishing domain and keyword databases.
- Risk scoring with explainable detection reasons.
- Alert notifications for dangerous sites.
- Scan history, analytics, and downloadable TXT/JSON reports.
- Local-only privacy model: no browsing data leaves the device.

## Project Structure

```
Version-Amynex-xmp-/

├── manifest.json
├── popup/
│   ├── popup.html
│   ├── popup.css
│   └── popup.js
├── background/
│   └── background.js
├── content/
│   └── injector.js
├── rules/
│   ├── phishing-rules.js
│   ├── url-analyzer.js
│   ├── dom-analyzer.js
│   ├── content-analyzer.js
│   └── reputation-engine.js
├── database/
│   └── threat-db.json
├── reports/
├── test-pages/
│   ├── safe.html
│   ├── suspicious.html
│   └── dangerous.html
├── assets/
├── screenshots/
└── README.md
```

## How It Works

1. The popup requests a scan for the current active tab.
2. The background service worker injects `content/injector.js` into the page.
3. The page script collects DOM, form, and content signals.
4. The popup combines URL, DOM, content, and reputation analysis into a final risk score.
5. The extension saves the scan history and displays analytics and export-ready reports.

## Installation

1. Open Chrome and go to `chrome://extensions`.
2. Enable `Developer mode`.
3. Click `Load unpacked`.
4. Select the project folder.
5. Click the Amynex.xmp toolbar icon.

## Testing

Use the local test pages in `test-pages/` to verify detection behavior:

- `safe.html` — benign page with no phishing indicators.
- `suspicious.html` — page with login keywords and credential fields.
- `dangerous.html` — page with external form actions, phishing phrases, and suspicious scripts.

## Privacy

- All analysis runs locally.
- No browsing data is sent to external servers.
- The extension only stores scan metadata and cached results.
- It never collects passwords or form values.

## Development Notes

- `manifest.json` defines the extension permissions and popup.
- `background/background.js` handles scan requests and script injection.
- `content/injector.js` inspects page DOM and text.
- `rules/*.js` implement the detection engine.
- `database/threat-db.json` stores local reputation data.

## Limitations

- Detection is heuristic and may produce false positives.
- Local threat intelligence is only as strong as the stored database.
- The extension does not analyze encrypted traffic.
- It is a demonstration tool and not a replacement for enterprise-grade security products.

## Future Improvements

- Add real-world phishing blocklists.
- Build an architecture diagram and screenshots.
- Improve brand impersonation detection.
- Add a settings page with custom trusted domains.
- Add a more detailed report export interface.
