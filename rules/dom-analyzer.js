export function analyzeDom(pageAnalysis, phishingRules) {
  const result = {
    score: 0,
    indicators: [],
    suspiciousKeywords: []
  };

  if (!pageAnalysis) {
    return result;
  }

  if (pageAnalysis.passwordFields > 0) {
    result.score += 15;
    result.indicators.push('Password Form');
  }

  if (pageAnalysis.externalFormActions?.length > 0) {
    result.score += 25;
    result.indicators.push('External Form Action');
  }

  if (pageAnalysis.hiddenInputs > 2) {
    result.score += 10;
    result.indicators.push('Hidden Inputs Detected');
  }

  if (pageAnalysis.credentialCollection) {
    result.score += 15;
    result.indicators.push('Credential Collection Form');
  }

  if (pageAnalysis.suspiciousKeywordsFound?.length > 0) {
    result.score += 10;
    result.suspiciousKeywords = pageAnalysis.suspiciousKeywordsFound;
    result.indicators.push('Suspicious Page Content');
  }

  return result;
}
