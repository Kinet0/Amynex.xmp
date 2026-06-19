import phishingRules from './phishing-rules.js';

function calculateEntropy(value) {
  if (!value || value.length === 0) {
    return 0;
  }

  const frequency = {};
  for (const char of value) {
    frequency[char] = (frequency[char] || 0) + 1;
  }

  return Object.values(frequency).reduce((entropy, count) => {
    const p = count / value.length;
    return entropy - p * Math.log2(p);
  }, 0);
}

export function analyzeUrl(rawUrl) {
  const result = {
    score: 0,
    indicators: [],
    keywordMatches: [],
    host: '',
    path: '',
    url: rawUrl
  };

  let url;
  try {
    url = new URL(rawUrl);
  } catch (error) {
    return result;
  }

  const hostname = url.hostname.toLowerCase();
  const normalizedUrl = rawUrl.toLowerCase();
  const path = `${url.pathname}${url.search}`;

  result.host = hostname;
  result.path = path;

  if (url.protocol === 'http:') {
    result.score += 20;
    result.indicators.push('HTTP Connection');
  }

  if (/^\d+(?:\.\d+){3}$/.test(hostname)) {
    result.score += 20;
    result.indicators.push('IP Address URL');
  }

  if (/^xn--/.test(hostname)) {
    result.score += 30;
    result.indicators.push('Punycode Domain');
  }

  const subdomainParts = hostname.split('.');
  if (subdomainParts.length >= 4) {
    result.score += 15;
    result.indicators.push('Multiple Subdomains');
  }

  if (normalizedUrl.length > 90) {
    result.score += 10;
    result.indicators.push('Excessive URL Length');
  }

  const keywordMatches = phishingRules.urlKeywords.filter((keyword) => normalizedUrl.includes(keyword));
  if (keywordMatches.length > 0) {
    result.score += 10;
    result.keywordMatches = [...new Set(keywordMatches)];
    result.indicators.push(`Suspicious Keywords in URL (${result.keywordMatches.join(', ')})`);
  }

  if (phishingRules.lookalikePatterns.some((pattern) => pattern.test(hostname))) {
    result.score += 25;
    result.indicators.push('Lookalike Domain');
  }

  const hostnameEntropy = calculateEntropy(hostname);
  const pathEntropy = calculateEntropy(path);
  if (hostnameEntropy >= 3.8 || pathEntropy >= 4.0) {
    result.score += 15;
    result.indicators.push('High URL Entropy');
  }

  result.score = Math.min(result.score, 100);
  return result;
}
