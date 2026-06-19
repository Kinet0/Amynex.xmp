// injector.js
// Runs inside the page context to collect DOM and form risk indicators.

(function () {
  const results = {
    formsFound: 0,
    passwordFields: 0,
    hiddenInputs: 0,
    externalFormActions: [],
    suspiciousKeywordsFound: []
  };

  const forms = document.forms;
  results.formsFound = forms.length;

  for (const form of forms) {
    const action = form.action || '';
    if (action && !action.includes(window.location.host)) {
      results.externalFormActions.push(action);
    }

    const inputs = form.querySelectorAll('input, button, textarea');
    for (const input of inputs) {
      const type = (input.type || '').toLowerCase();
      const name = (input.name || '').toLowerCase();
      const placeholder = (input.placeholder || '').toLowerCase();
      const id = (input.id || '').toLowerCase();

      if (type === 'password') {
        results.passwordFields += 1;
      }

      if (type === 'hidden') {
        results.hiddenInputs += 1;
      }

      if (['text', 'email', 'tel', 'search', 'url'].includes(type) || name.includes('user') || name.includes('email') || placeholder.includes('user') || placeholder.includes('email') || id.includes('user') || id.includes('email')) {
        if (input.type !== 'password') {
          results.usernameField = true;
        }
      }
    }
  }

  const pageText = document.body ? document.body.innerText.toLowerCase() : '';
  const suspiciousWords = [
    'login',
    'signin',
    'verify',
    'secure',
    'update',
    'account',
    'password',
    'banking',
    'confirm'
  ];

  results.suspiciousKeywordsFound = suspiciousWords.filter((keyword) => pageText.includes(keyword));

  // Return the analysis results to the background service worker.
  return results;
})();
