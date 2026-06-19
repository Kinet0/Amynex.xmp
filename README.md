# PhishGuard v1

PhishGuard v1 is a beginner-friendly Chrome extension for real-time phishing detection. It analyzes the current website URL and page content, computes a risk score, and stores scan history for portfolio-ready cybersecurity demonstrations.

## Project Structure

```
phishguard-v1/

├── manifest.json
│
├── popup/
│   ├── popup.html
│   ├── popup.css
│   └── popup.js
│
├── content/
│   ├── content.js
│   └── injector.js
│
├── rules/
│   └── phishing-rules.js
│
├── storage/
│
├── assets/
│
└── README.md
```

## How it Works

- `manifest.json` defines the extension and required permissions.
- `popup/popup.html` is the UI displayed when the user clicks the extension icon.
- `popup/popup.js` requests a scan and renders risk score, classification, indicators, and recent scan history.
- `content/content.js` is the background service worker that handles messages and injects `content/injector.js` into web pages.
- `content/injector.js` runs in the page context and inspects DOM elements for phishing indicators.
- `rules/phishing-rules.js` contains threat patterns and keyword rules.

## Chrome APIs Used

- `chrome.tabs`
  - Gets the current active tab and its URL.
- `chrome.storage.local`
  - Stores scan history and risk data locally.
- `chrome.scripting`
  - Injects the scanner script into the webpage to analyze DOM content.

## Installation

1. Open Chrome and navigate to `chrome://extensions`.
2. Enable `Developer mode`.
3. Click `Load unpacked`.
4. Select the `AAA-version1-chromephishing-exetension` folder.
5. Click the PhishGuard icon in the toolbar.

## Testing Safely

- Test on simple websites like `https://example.com`.
- Avoid scanning real banking or login pages until you understand how the extension works.
- Use local HTML pages or known safe test pages.

## Future Version 2 Ideas

- Browser notifications for dangerous sites.
- Threat intelligence integration with free phishing blocklists.
- Machine learning risk scoring with labeled phishing datasets.
- Cloud-based database for known phishing domains and URL reputation.
- Better page indicators and user alert modals.
