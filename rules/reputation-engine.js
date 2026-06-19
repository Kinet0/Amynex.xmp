// reputation-engine.js
// Compares the current domain against local threat intelligence.

export function analyzeReputation(rawUrl, threatDb) {
  const result = {
    score: 0,
    indicators: [],
    reputationLabel: 'No threat indicators'
  };

  if (!threatDb || !rawUrl) {
    return result;
  }

  let url;
  try {
    url = new URL(rawUrl);
  } catch (error) {
    return result;
  }

  const hostname = url.hostname.toLowerCase();

  const phishingMatch = threatDb.phishing_domains?.find((domain) => {
    const normalized = domain.toLowerCase();
    return hostname === normalized || hostname.endsWith(`.${normalized}`);
  });

  if (phishingMatch) {
    result.score += 40;
    result.indicators.push('Known phishing domain');
    result.reputationLabel = 'Known phishing domain';
    return result;
  }

  const trustedMatch = threatDb.trusted_domains?.find((domain) => {
    const normalized = domain.toLowerCase();
    return hostname === normalized || hostname.endsWith(`.${normalized}`);
  });

  if (trustedMatch) {
    result.reputationLabel = 'Trusted domain';
    return result;
  }

  const suspiciousMatch = threatDb.keywords?.find((keyword) => hostname.includes(keyword));
  if (suspiciousMatch) {
    result.score += 20;
    result.indicators.push('Suspicious domain keyword');
    result.reputationLabel = 'Suspicious domain keyword';
  }

  return result;
}
