// injector.js
// Runs inside the page context to collect DOM, form, and content threat signals.

(function () {
  const suspiciousWords = [
    'login',
    'signin',
    'verify',
    'secure',
    'update',
    'account',
    'password',
    'banking',
    'confirm',
    'security alert',
    'verify account',
    'account suspended',
    'urgent action required',
    'confirm identity',
    'immediate response needed',
    'payment failed',
    'limited time'
  ];

  const suspiciousScripts = ['eval(', 'atob(', 'document.write(', 'location.replace', 'location.href'];
  const suspiciousBrands = ['paypa1', 'g00gle', 'amaz0n', 'micr0soft', 'apple-login', 'paypal-secure', 'amazon-login'];

  function normalizeText(value) {
    return String(value || '').toLowerCase();
  }

  function findMatchingItems(source, items) {
    return items.filter((item) => source.includes(item));
  }

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
      password: false,
      creditCard: false
    },
    credentialCollection: false,
    suspiciousRedirects: [],
    suspiciousJsFunctions: [],
    phishingPhrases: [],
    brandImpersonation: []
  };

  const forms = Array.from(document.forms);
  results.formsFound = forms.length;

  forms.forEach((form) => {
    const action = normalizeText(form.action);
    if (action) {
      try {
        const actionHost = new URL(action, window.location.href).host;
        if (actionHost && actionHost !== window.location.host) {
          results.externalFormActions.push(action);
        }
      } catch {
        results.externalFormActions.push(action);
      }
    }

    const inputs = Array.from(form.querySelectorAll('input, textarea, select'));

    inputs.forEach((input) => {
      const type = normalizeText(input.type);
      const name = normalizeText(input.name);
      const placeholder = normalizeText(input.placeholder);
      const id = normalizeText(input.id);
      const label = normalizeText(document.querySelector(`label[for="${input.id}"]`)?.innerText || '');

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

      if (name.includes('card') || name.includes('cc') || placeholder.includes('card') || placeholder.includes('cc') || id.includes('card') || id.includes('cc') || label.includes('card')) {
        results.credentialFields.creditCard = true;
      }
    });
  });

  const credentialCount = Object.values(results.credentialFields).filter(Boolean).length;
  results.credentialCollection = credentialCount >= 2;

  const pageText = normalizeText(document.body?.innerText || '');
  results.suspiciousKeywordsFound = suspiciousWords.filter((keyword) => pageText.includes(keyword));
  results.phishingPhrases = suspiciousWords.filter((phrase) => pageText.includes(phrase));
  results.brandImpersonation = findMatchingItems(pageText, suspiciousBrands);

  const inlineText = normalizeText(document.documentElement?.innerHTML || '');
  results.suspiciousJsFunctions = suspiciousScripts.filter((fn) => inlineText.includes(fn));

  const redirectSources = [];
  if (inlineText.includes('location.replace')) redirectSources.push('location.replace');
  if (inlineText.includes('location.href')) redirectSources.push('location.href');

  const metaRefresh = Array.from(document.querySelectorAll('meta[http-equiv="refresh"]'));
  if (metaRefresh.length > 0) {
    redirectSources.push('meta refresh');
  }

  results.suspiciousRedirects = Array.from(new Set(redirectSources));

  return results;
})();
