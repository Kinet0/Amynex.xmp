// injector.js
// Runs inside the page context to collect DOM and form risk indicators.

(function () {
  const results = {
    formsFound: 0,
    passwordFields: 0,
    hiddenInputs: 0,
    externalFormActions: [],
    suspiciousKeywordsFound: [],
    credentialFields: {
      email: false,
      username: false,
      phone: false,
      password: false
    },
    credentialCollection: false
  };

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

  const forms = Array.from(document.forms);
  results.formsFound = forms.length;

  function normalizeText(value) {
    return String(value || '').toLowerCase();
  }

  forms.forEach((form) => {
    const action = normalizeText(form.action);
    if (action) {
      try {
        const actionHost = new URL(action, window.location.href).host;
        if (actionHost && actionHost !== window.location.host) {
          results.externalFormActions.push(action);
        }
      } catch (error) {
        results.externalFormActions.push(action);
      }
    }

    const inputs = Array.from(form.querySelectorAll('input, textarea, select'));

    inputs.forEach((input) => {
      const type = normalizeText(input.type);
      const name = normalizeText(input.name);
      const placeholder = normalizeText(input.placeholder);
      const id = normalizeText(input.id);
      const label = normalizeText(document.querySelector(`label[for="${input.id}"]`)?.innerText);

      if (type === 'password') {
        results.passwordFields += 1;
        results.credentialFields.password = true;
      }

      if (type === 'hidden') {
        results.hiddenInputs += 1;
      }

      if (type === 'email' || name.includes('email') || placeholder.includes('email') || id.includes('email') || label.includes('email')) {
        results.credentialFields.email = true;
      }

      if (name.includes('user') || name.includes('username') || placeholder.includes('user') || placeholder.includes('username') || id.includes('user') || id.includes('username') || label.includes('user') || label.includes('username')) {
        results.credentialFields.username = true;
      }

      if (type === 'tel' || name.includes('phone') || placeholder.includes('phone') || id.includes('phone') || label.includes('phone')) {
        results.credentialFields.phone = true;
      }
    });
  });

  const credentialCount = Object.values(results.credentialFields).filter(Boolean).length;
  results.credentialCollection = credentialCount >= 2;

  const pageText = normalizeText(document.body?.innerText);
  results.suspiciousKeywordsFound = suspiciousWords.filter((keyword) => pageText.includes(keyword));

  return results;
})();
