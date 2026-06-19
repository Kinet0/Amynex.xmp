// content-analyzer.js
// Analyzes page text for phishing language and social engineering indicators.

import phishingRules from './phishing-rules.js';

export function analyzeContent(pageAnalysis) {
  const result = {
    score: 0,
    indicators: []
  };

  if (!pageAnalysis) {
    return result;
  }

  const phrases = pageAnalysis.phishingPhrases || [];
  if (phrases.length > 0) {
    result.score += 10;
    result.indicators.push(`Phishing language detected: ${phrases.join(', ')}`);
  }

  const brandMatches = pageAnalysis.brandImpersonation || [];
  if (brandMatches.length > 0) {
    result.score += 25;
    result.indicators.push(`Brand impersonation detected: ${brandMatches.join(', ')}`);
  }

  if (pageAnalysis.suspiciousKeywordsFound?.length > 0) {
    result.score += 10;
    result.indicators.push(`Suspicious page keywords: ${pageAnalysis.suspiciousKeywordsFound.join(', ')}`);
  }

  return result;
}
