// popup.js
// Popup script that requests page scanning and renders analysis results.

import phishingRules from '../rules/phishing-rules.js';

const currentUrlEl = document.getElementById('currentUrl');
const riskScoreEl = document.getElementById('riskScore');
const classificationEl = document.getElementById('classification');
const indicatorListEl = document.getElementById('indicatorList');
const scanHistoryEl = document.getElementById('scanHistory');
const refreshButton = document.getElementById('refreshButton');

const maxRiskScore = 100;

function classifyScore(score) {
  if (score >= 60) return 'Dangerous';
  if (score >= 30) return 'Suspicious';
  return 'Safe';
}

function getClassificationColor(classification) {
  switch (classification) {
    case 'Dangerous':
      return '#ff5f7a';
    case 'Suspicious':
      return '#ffd166';
    default:
      return '#7efc7d';
  }
}

function renderIndicators(indicators) {
  indicatorListEl.innerHTML = '';
  if (!indicators || indicators.length === 0) {
    indicatorListEl.innerHTML = '<div class="indicator-item">No suspicious indicators found.</div>';
    return;
  }

  indicators.forEach((text) => {
    const item = document.createElement('div');
    item.className = 'indicator-item';
    item.textContent = `✓ ${text}`;
    indicatorListEl.appendChild(item);
  });
}

function renderHistory(history) {
  scanHistoryEl.innerHTML = '';
  if (!history || history.length === 0) {
    scanHistoryEl.textContent = 'No scans recorded yet.';
    return;
  }

  history.slice(0, 5).forEach((entry) => {
    const row = document.createElement('div');
    row.className = 'history-item';
    row.innerHTML = `
      <span>${entry.url}</span>
      <span>${entry.classification}</span>
    `;
    scanHistoryEl.appendChild(row);
  });
}

function saveScanHistory(entry) {
  chrome.storage.local.get(['scanHistory'], (result) => {
    const history = result.scanHistory || [];
    history.unshift(entry);
    const trimmed = history.slice(0, 20);
    chrome.storage.local.set({ scanHistory: trimmed });
    renderHistory(trimmed);
  });
}

function scanCurrentTab() {
  chrome.runtime.sendMessage({ type: 'scan-current-tab' }, (response) => {
    if (!response || response.error) {
      currentUrlEl.textContent = 'Unable to scan page.';
      return;
    }

    currentUrlEl.textContent = response.url;
    if (response.analysis) {
      updateResults(response.url, response.analysis);
    }
  });
}

function updateResults(url, analysis) {
  const indicators = [];
  let score = 0;

  const normalizedUrl = url.toLowerCase();
  const urlObject = new URL(url);

  if (/^http:\/\/.+/i.test(url)) {
    score += 20;
    indicators.push('HTTP Connection');
  }

  const hostname = urlObject.hostname;
  if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) {
    score += 20;
    indicators.push('IP Address URL');
  }

  if (hostname.split('.').length >= 4) {
    score += 15;
    indicators.push('Multiple Subdomains');
  }

  if (normalizedUrl.length > 90) {
    score += 10;
    indicators.push('Long URL');
  }

  phishingRules.urlKeywords.forEach((keyword) => {
    if (normalizedUrl.includes(keyword)) {
      score += 10;
      if (!indicators.includes('Suspicious Keywords')) {
        indicators.push('Suspicious Keywords');
      }
    }
  });

  if (phishingRules.lookalikePatterns.some((pattern) => pattern.test(hostname))) {
    score += 25;
    indicators.push('Lookalike Domain');
  }

  if (analysis.passwordFields > 0) {
    score += 15;
    indicators.push('Login Form Detected');
  }

  if (analysis.externalFormActions.length > 0) {
    score += 25;
    indicators.push('External Form Action');
  }

  if (analysis.hiddenInputs > 2) {
    score += 10;
    indicators.push('Hidden Inputs Detected');
  }

  if (analysis.suspiciousKeywordsFound.length > 0) {
    indicators.push(`Page keywords: ${analysis.suspiciousKeywordsFound.slice(0, 4).join(', ')}`);
  }

  score = Math.min(score, maxRiskScore);

  const classification = classifyScore(score);
  classificationEl.textContent = classification;
  classificationEl.style.background = getClassificationColor(classification);
  riskScoreEl.textContent = `${score}/100`;
  renderIndicators(indicators);

  saveScanHistory({
    url: urlObject.hostname,
    riskScore: score,
    classification,
    date: new Date().toISOString()
  });
}

refreshButton.addEventListener('click', scanCurrentTab);

chrome.storage.local.get(['scanHistory'], (result) => {
  renderHistory(result.scanHistory || []);
});

scanCurrentTab();
