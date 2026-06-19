chrome.runtime.onInstalled.addListener(() => {
  console.log('PhishGuard v3 installed.');
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message && message.type === 'scan-current-tab') {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tab = tabs[0];
      if (!tab || !tab.url) {
        sendResponse({ error: 'Unable to determine active tab.' });
        return;
      }

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
