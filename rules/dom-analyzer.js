export function analyzeDom(pageAnalysis) {
  const result = {
    score: 0,
    structuralScore: 0,
    technicalScore: 0,
    indicators: []
  };

  if (!pageAnalysis) {
    return result;
  }

  if (pageAnalysis.passwordFields > 0) {
    result.structuralScore += 15;
    result.indicators.push('Password Field Detected');
  }

  if (pageAnalysis.credentialCollection) {
    result.structuralScore += 20;
    result.indicators.push('Credential Collection Form');
  }

  if (pageAnalysis.externalFormActions?.length > 0) {
    result.structuralScore += 25;
    result.indicators.push('External Form Action');
  }

  if (pageAnalysis.hiddenInputs > 2) {
    result.structuralScore += 10;
    result.indicators.push('Hidden Inputs Detected');
  }

  if (pageAnalysis.suspiciousRedirects?.length > 0) {
    result.technicalScore += 15;
    result.indicators.push('Suspicious Redirect Behavior');
  }

  if (pageAnalysis.suspiciousJsFunctions?.length > 0) {
    result.technicalScore += 10;
    result.indicators.push('Suspicious JavaScript Functions');
  }

  result.score = Math.min(result.structuralScore + result.technicalScore, 100);
  return result;
}