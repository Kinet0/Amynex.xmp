// phishing-rules.js
// Reusable phishing rules and detection patterns for PhishGuard v3.

const phishingRules = {
  urlKeywords: [
    'login',
    'signin',
    'verify',
    'secure',
    'update',
    'account',
    'password',
    'banking',
    'confirm'
  ],
  lookalikePatterns: [
    /paypa1\./i,
    /amaz0n\./i,
    /g00gle\./i,
    /micr0soft\./i,
    /micros0ft\./i,
    /amaz0n-security/i,
    /apple-login/i,
    /paypal-secure/i,
    /amazon-login/i
  ],
  brandPatterns: [
    { name: 'PayPal', pattern: /paypa1|paypal(?:[-_.]?secure)?/i },
    { name: 'Google', pattern: /g00gle|google[-_.]?login/i },
    { name: 'Microsoft', pattern: /micr0soft|microsoft[-_.]?alert/i },
    { name: 'Amazon', pattern: /amaz0n|amazon[-_.]?security/i },
    { name: 'Apple', pattern: /apple[-_.]?verify|xn--apple/i },
    { name: 'Facebook', pattern: /faceb00k|facebook[-_.]?security/i },
    { name: 'Netflix', pattern: /netflix[-_.]?login/i }
  ],
  phishingPhrases: [
    'verify account',
    'account suspended',
    'security alert',
    'urgent action required',
    'confirm identity',
    'immediate response needed',
    'payment failed',
    'limited time'
  ],
  technicalIndicators: [
    'eval(',
    'atob(',
    'document.write(',
    'location.replace',
    'location.href'
  ],
  formIndicators: [
    'email',
    'user',
    'username',
    'phone',
    'tel',
    'password',
    'card',
    'cc-number'
  ]
};

export default phishingRules;
