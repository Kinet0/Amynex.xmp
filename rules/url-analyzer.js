import phishingRules from './phishing-rules.js';

export function analyzeUrl(rawUrl, threatDb) {
  const result = {
    score: 0,
    indicators: [],
    keywordMatches: [],
    reputationReason: null
  };

  let url;
  try {
    url = new URL(rawUrl);
  } catch (error) {
    return result;
  }

  const hostname = url.hostname.toLowerCase();
  const normalizedUrl = rawUrl.toLowerCase();

  if (url.protocol === 'http:') {
    result.score += 20;
    result.indicators.push('HTTP Connection');
  }

  if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) {
    result.score += 20;
    result.indicators.push('IP Address URL');
  }

  const subdomainParts = hostname.split('.');
  if (subdomainParts.length >= 4) {
    result.score += 15;
    result.indicators.push('Multiple Subdomains');
  }

  if (normalizedUrl.length > 90) {
    result.score += 10;
    result.indicators.push('Long URL');
  }

  const keywordMatches = phishingRules.urlKeywords.filter((keyword) => normalizedUrl.includes(keyword));
  if (keywordMatches.length > 0) {
    result.score += 10;
    result.keywordMatches = [...new Set(keywordMatches)];
    result.indicators.push('Suspicious Keywords in URL');
  }

  if (phishingRules.lookalikePatterns.some((pattern) => pattern.test(hostname))) {
    result.score += 25;
    result.indicators.push('Lookalike Domain');
  }

  if (threatDb?.phishing_domains) {
    const matchedDomain = threatDb.phishing_domains.find((domain) => {
      const normalized = domain.toLowerCase();
      return hostname === normalized || hostname.endsWith(`.${normalized}`);
    });

    if (matchedDomain) {
      result.score += 40;
      result.reputationReason = 'Known phishing domain';
      result.indicators.push('Blacklist Match');
    }
  }

  if (!result.reputationReason && threatDb?.suspicious_keywords) {
    const keywordMatch = threatDb.suspicious_keywords.find((keyword) => hostname.includes(keyword));
    if (keywordMatch) {
      result.score += 20;
      result.reputationReason = 'Suspicious domain keyword';
      result.indicators.push('Suspicious Domain Keyword');
    }
  }

  if (!result.reputationReason) {
    result.reputationReason = 'No threat indicators';
  }

  result.score = Math.min(result.score, 100);
  return result;
}
