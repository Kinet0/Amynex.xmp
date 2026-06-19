// popup.js
// PhishGuard v2 popup controller.

import phishingRules from '../rules/phishing-rules.js';
import { analyzeUrl } from '../rules/url-analyzer.js';
import { analyzeDom } from '../rules/dom-analyzer.js';

const currentUrlEl = document.getElementById('currentUrl');
const riskScoreEl = document.getElementById('riskScore');
const classificationEl = document.getElementById('classification');
const indicatorListEl = document.getElementById('indicatorList');
const scanHistoryEl = document.getElementById('scanHistory');
const refreshButton = document.getElementById('refreshButton');
const downloadTxtButton = document.getElementById('downloadTxtButton');
const downloadJsonButton = document.getElementById('downloadJsonButton');
const threatReputationEl = document.getElementById('threatReputation');
const lastScanTimeEl = document.getElementById('lastScanTime');

let threatDb = null;
let latestScan = null;
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

function formatTimestamp(value) {
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
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
      <span>${formatTimestamp(entry.timestamp)}</span>
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

async function loadThreatDb() {
  if (threatDb) return threatDb;
  const response = await fetch(chrome.runtime.getURL('database/threat-db.json'));
  threatDb = await response.json();
  return threatDb;
}

function createTxtReport(scan) {
  return `Website: ${scan.url}\n\nRisk Score: ${scan.score}/100\nClassification: ${scan.classification}\n\nIndicators:\n${scan.reasons.map((reason) => `✓ ${reason}`).join('\n')}\n\nThreat Reputation: ${scan.reputationLabel}\n\nRecommendation:\nDo not submit credentials if the site appears suspicious.\n`;
}

function downloadReport(filename, content, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

function showNotification(score, classification, url) {
  if (score < 60) return;

  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/w8AAwMBApN5d6kAAAAASUVORK5CYII=',
    title: '⚠ PHISHING WARNING',
    message: `${classification} website detected:\n${new URL(url).hostname} should be treated with caution.`, 
    priority: 2
  });
}

function combineAnalysis(url, urlAnalysis, domAnalysis) {
  const score = Math.min(urlAnalysis.score + domAnalysis.score, maxRiskScore);
  const reasons = Array.from(new Set([].concat(
    urlAnalysis.reputationReason ? [urlAnalysis.reputationReason] : [],
    urlAnalysis.indicators,
    domAnalysis.indicators
  )));

  if (urlAnalysis.keywordMatches?.length) {
    reasons.push(`URL keywords: ${urlAnalysis.keywordMatches.join(', ')}`);
  }

  if (domAnalysis.suspiciousKeywords?.length) {
    reasons.push(`Page keywords: ${domAnalysis.suspiciousKeywords.slice(0, 5).join(', ')}`);
  }

  return {
    url,
    score,
    classification: classifyScore(score),
    reasons,
    reputationLabel: urlAnalysis.reputationReason || 'No threat indicators',
    timestamp: new Date().toISOString(),
    details: {
      urlAnalysis,
      domAnalysis
    }
  };
}

function updateResults(url, analysis) {
  latestScan = analysis;
  currentUrlEl.textContent = url;
  threatReputationEl.textContent = analysis.reputationLabel;
  lastScanTimeEl.textContent = formatTimestamp(analysis.timestamp);
  riskScoreEl.textContent = `${analysis.score}/100`;
  classificationEl.textContent = analysis.classification;
  classificationEl.style.background = getClassificationColor(analysis.classification);
  renderIndicators(analysis.reasons);
  saveScanHistory(analysis);
  showNotification(analysis.score, analysis.classification, url);
}

function scanCurrentTab() {
  currentUrlEl.textContent = 'Scanning site...';
  loadThreatDb()
    .then(() => {
      chrome.runtime.sendMessage({ type: 'scan-current-tab' }, (response) => {
        if (!response || response.error) {
          currentUrlEl.textContent = 'Unable to scan page.';
          return;
        }

        const urlAnalysis = analyzeUrl(response.url, threatDb);
        const domAnalysis = analyzeDom(response.analysis, phishingRules);
        const combined = combineAnalysis(response.url, urlAnalysis, domAnalysis);
        updateResults(response.url, combined);
      });
    })
    .catch(() => {
      currentUrlEl.textContent = 'Unable to load threat database.';
    });
}

downloadTxtButton.addEventListener('click', () => {
  if (!latestScan) return;
  const report = createTxtReport(latestScan);
  downloadReport('phishguard-report.txt', report, 'text/plain');
});

downloadJsonButton.addEventListener('click', () => {
  if (!latestScan) return;
  downloadReport('phishguard-report.json', JSON.stringify(latestScan, null, 2), 'application/json');
});

refreshButton.addEventListener('click', scanCurrentTab);

chrome.storage.local.get(['scanHistory'], (result) => {
  renderHistory(result.scanHistory || []);
});

scanCurrentTab();
