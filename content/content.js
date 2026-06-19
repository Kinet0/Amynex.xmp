// content.js
// Acts as the background service worker and script injector for PhishGuard v3.

chrome.runtime.onInstalled.addListener(() => {
  console.log('PhishGuard v3 installed.');
});

// Listen for the popup asking to scan the current active tab.
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message && message.type === 'scan-current-tab') {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tab = tabs[0];
      if (!tab || !tab.url) {
        sendResponse({ error: 'Unable to determine active tab.' });
        return;
      }

      // Inject the phishing scanner into the current tab.
      chrome.scripting.executeScript(
        {
          target: { tabId: tab.id },
          files: ['content/injector.js']
        },
        (results) => {
          if (chrome.runtime.lastError) {
            sendResponse({ error: chrome.runtime.lastError.message });
            return;
          }

          const analysis = results && results[0] && results[0].result;
          sendResponse({ url: tab.url, analysis });
        }
      );
    });

    return true;
  }
});
