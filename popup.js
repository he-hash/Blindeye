// BlindEye Popup Script

document.addEventListener('DOMContentLoaded', () => {
  loadThreats();
  setupEventListeners();
});

function setupEventListeners() {
  document.getElementById('refresh-btn').addEventListener('click', () => {
    loadThreats();
  });

  document.getElementById('clear-btn').addEventListener('click', () => {
    clearThreats();
  });
}

async function loadThreats() {
  try {
    // Get threats from background script
    chrome.runtime.sendMessage({ action: 'get_threats' }, (response) => {
      const threats = response?.threats || [];
      displayThreats(threats);
      updateStats(threats);
    });

    // Also query content script for current alerts
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.id) {
      chrome.tabs.sendMessage(tab.id, { action: 'get_alerts' }, (response) => {
        if (response?.alerts) {
          displayThreats(response.alerts);
          updateStats(response.alerts);
        }
      });
    }
  } catch (error) {
    console.error('[BlindEye] Error loading threats:', error);
  }
}

function displayThreats(threats) {
  const threatsList = document.getElementById('threats-list');
  const status = document.getElementById('status');
  const statusText = status.querySelector('.status-text');

  if (!threats || threats.length === 0) {
    threatsList.innerHTML = `
      <div class="empty-state">
        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
          <path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
        <p>No threats detected</p>
        <span>Your browsing is secure</span>
      </div>
    `;
    status.classList.remove('alert');
    status.classList.add('safe');
    statusText.textContent = 'Protected';
    return;
  }

  // Update status
  status.classList.remove('safe');
  status.classList.add('alert');
  statusText.textContent = 'Threats Found';

  // Sort threats by timestamp (newest first)
  threats.sort((a, b) => b.timestamp - a.timestamp);

  // Display threats
  threatsList.innerHTML = threats.map(threat => {
    const timeAgo = getTimeAgo(threat.timestamp);
    const severityClass = threat.severity.toLowerCase();
    
    return `
      <div class="threat-item ${severityClass}">
        <div class="threat-header">
          <span class="threat-type">${formatThreatType(threat.type)}</span>
          <span class="threat-severity">${threat.severity}</span>
        </div>
        <div class="threat-details">${escapeHtml(threat.details)}</div>
        <div class="threat-element">Element: &lt;${threat.element}&gt;</div>
        <div class="threat-time">${timeAgo}</div>
      </div>
    `;
  }).join('');
}

function updateStats(threats) {
  const threatCount = document.getElementById('threat-count');
  const elementsMonitored = document.getElementById('elements-monitored');

  threatCount.textContent = threats.length;
  
  // Estimate monitored elements (in a real scenario, this would come from content script)
  const uniqueElements = new Set(threats.map(t => t.element)).size;
  elementsMonitored.textContent = Math.max(uniqueElements * 5, 10);
}

function clearThreats() {
  const threatsList = document.getElementById('threats-list');
  const status = document.getElementById('status');
  const statusText = status.querySelector('.status-text');

  threatsList.innerHTML = `
    <div class="empty-state">
      <svg width="48" height="48" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
      <p>No threats detected</p>
      <span>Your browsing is secure</span>
    </div>
  `;

  status.classList.remove('alert');
  status.classList.add('safe');
  statusText.textContent = 'Protected';

  document.getElementById('threat-count').textContent = '0';

  // Clear badge
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0]) {
      chrome.action.setBadgeText({ tabId: tabs[0].id, text: '' });
    }
  });
}

function formatThreatType(type) {
  return type.replace(/_/g, ' ');
}

function getTimeAgo(timestamp) {
  const seconds = Math.floor((Date.now() - timestamp) / 1000);
  
  if (seconds < 60) return 'Just now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

function escapeHtml(text) {
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };
  return text.replace(/[&<>"']/g, m => map[m]);
}
