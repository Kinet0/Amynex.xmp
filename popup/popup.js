// popup.js
// Amynex.xmp popup controller.

import { analyzeUrl } from '../rules/url-analyzer.js';
import { analyzeDom } from '../rules/dom-analyzer.js';
import { analyzeContent } from '../rules/content-analyzer.js';
import { analyzeReputation } from '../rules/reputation-engine.js';

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
const totalScansEl = document.getElementById('totalScans');
const safeCountEl = document.getElementById('safeCount');
const suspiciousCountEl = document.getElementById('suspiciousCount');
const dangerousCountEl = document.getElementById('dangerousCount');
const detectionExplanationEl = document.getElementById('detectionExplanation');
const recommendationTextEl = document.getElementById('recommendationText');

let threatDb = null;
let latestScan = null;
const cacheTTL = 10 * 60 * 1000;
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

function renderExplanation(reasons) {
  detectionExplanationEl.innerHTML = '';
  if (!reasons || reasons.length === 0) {
    detectionExplanationEl.textContent = 'No suspicious behavior detected during the scan.';
    return;
  }

  detectionExplanationEl.innerHTML = reasons
    .map((reason) => `<div class="explanation-item">${reason}</div>`)
    .join('');
}

function computeStats(history) {
  const stats = {
    totalScans: history.length,
    safeCount: 0,
    suspiciousCount: 0,
    dangerousCount: 0
  };

  history.forEach((entry) => {
    if (entry.classification === 'Dangerous') stats.dangerousCount += 1;
    else if (entry.classification === 'Suspicious') stats.suspiciousCount += 1;
    else stats.safeCount += 1;
  });

  return stats;
}

function renderStats(stats) {
  totalScansEl.textContent = stats.totalScans;
  safeCountEl.textContent = stats.safeCount;
  suspiciousCountEl.textContent = stats.suspiciousCount;
  dangerousCountEl.textContent = stats.dangerousCount;
}

function renderHistory(history) {
  scanHistoryEl.innerHTML = '';
  if (!history || history.length === 0) {
    scanHistoryEl.textContent = 'No scans recorded yet.';
    renderStats(computeStats([]));
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

  renderStats(computeStats(history));
}

function saveScanHistory(entry) {
  chrome.storage.local.get(['scanHistory', 'scanCache'], (result) => {
    const history = result.scanHistory || [];
    const updatedHistory = [entry, ...history].slice(0, 50);
    const cache = result.scanCache || {};
    cache[entry.url] = entry;

    chrome.storage.local.set({ scanHistory: updatedHistory, scanCache: cache }, () => {
      renderHistory(updatedHistory);
    });
  });
}

function getCachedScan(url) {
  return new Promise((resolve) => {
    chrome.storage.local.get(['scanCache'], (result) => {
      const cache = result.scanCache || {};
      const entry = cache[url];
      if (!entry) {
        resolve(null);
        return;
      }

      const age = Date.now() - new Date(entry.timestamp).getTime();
      resolve(age < cacheTTL ? entry : null);
    });
  });
}

async function loadThreatDb() {
  if (threatDb) return threatDb;
  const response = await fetch(chrome.runtime.getURL('database/threat-db.json'));
  threatDb = await response.json();
  return threatDb;
}

function createTxtReport(scan) {
  return `Website: ${scan.url}\n\nRisk Score: ${scan.score}/100\nClassification: ${scan.classification}\n\nIndicators:\n${scan.reasons.map((reason) => `✓ ${reason}`).join('\n')}\n\nThreat Reputation: ${scan.reputationLabel}\n\nRecommendation:\n${buildRecommendation(scan.classification)}\n`;
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

function buildRecommendation(classification) {
  switch (classification) {
    case 'Dangerous':
      return 'This page appears dangerous. Do not enter credentials and close the tab if possible.';
    case 'Suspicious':
      return 'Exercise caution. Review the page carefully before submitting any sensitive information.';
    default:
      return 'This page appears safe based on current analysis, but always remain vigilant.';
  }
}

function combineAnalysis(url, urlAnalysis, domAnalysis, contentAnalysis, reputationAnalysis) {
  const weightedScore = Math.round(
    urlAnalysis.score * 0.3 +
    domAnalysis.score * 0.25 +
    reputationAnalysis.score * 0.25 +
    contentAnalysis.score * 0.1 +
    domAnalysis.technicalScore * 0.1
  );

  const indications = [
    ...urlAnalysis.indicators,
    ...domAnalysis.indicators,
    ...contentAnalysis.indicators,
    ...reputationAnalysis.indicators
  ];

  return {
    url,
    score: Math.min(weightedScore, maxRiskScore),
    classification: classifyScore(weightedScore),
    reasons: Array.from(new Set(indications)),
    reputationLabel: reputationAnalysis.reputationLabel,
    timestamp: new Date().toISOString(),
    details: {
      urlAnalysis,
      domAnalysis,
      contentAnalysis,
      reputationAnalysis
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
  renderExplanation(analysis.reasons);
  recommendationTextEl.textContent = buildRecommendation(analysis.classification);
  saveScanHistory(analysis);
  showNotification(analysis.score, analysis.classification, url);
}

function getActiveTab() {
  return new Promise((resolve) => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      resolve(tabs[0]);
    });
  });
}

async function scanCurrentTab() {
  currentUrlEl.textContent = 'Scanning site...';

  try {
    await loadThreatDb();
    const tab = await getActiveTab();
    if (!tab || !tab.url) {
      currentUrlEl.textContent = 'Unable to determine active tab.';
      return;
    }

    const cached = await getCachedScan(tab.url);
    if (cached) {
      updateResults(tab.url, cached);
      return;
    }

    chrome.runtime.sendMessage({ type: 'scan-current-tab' }, (response) => {
      if (!response || response.error) {
        currentUrlEl.textContent = 'Unable to scan page.';
        return;
      }

      const urlAnalysis = analyzeUrl(response.url);
      const domAnalysis = analyzeDom(response.analysis);
      const contentAnalysis = analyzeContent(response.analysis);
      const reputationAnalysis = analyzeReputation(response.url, threatDb);
      const combined = combineAnalysis(response.url, urlAnalysis, domAnalysis, contentAnalysis, reputationAnalysis);
      updateResults(response.url, combined);
    });
  } catch (error) {
    currentUrlEl.textContent = 'Unable to load threat database.';
  }
}

downloadTxtButton.addEventListener('click', () => {
  if (!latestScan) return;
  const report = createTxtReport(latestScan);
  downloadReport('amynex-report.txt', report, 'text/plain');
});

downloadJsonButton.addEventListener('click', () => {
  if (!latestScan) return;
  downloadReport('amynex-report.json', JSON.stringify(latestScan, null, 2), 'application/json');
});

refreshButton.addEventListener('click', scanCurrentTab);

chrome.storage.local.get(['scanHistory'], (result) => {
  renderHistory(result.scanHistory || []);
});

scanCurrentTab();
