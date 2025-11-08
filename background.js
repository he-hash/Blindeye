// BlindEye Background Service Worker

let threatsByTab = {};

// Listen for messages from content script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  const tabId = sender.tab?.id;

  if (request.action === 'threat_detected') {
    handleThreatDetection(tabId, request.threat, request.url);
  }

  if (request.action === 'update_badge') {
    updateBadge(tabId, request.count);
  }
});

function handleThreatDetection(tabId, threat, url) {
  if (!tabId) return;

  // Store threat data
  if (!threatsByTab[tabId]) {
    threatsByTab[tabId] = [];
  }
  threatsByTab[tabId].push(threat);

  // Change icon to red (alert state)
  chrome.action.setIcon({
    tabId: tabId,
    path: {
      16: 'icons/alert-16.png',
      48: 'icons/alert-48.png',
      128: 'icons/alert-128.png',
    },
  });

  // Show notification for critical threats
  if (threat.severity === 'CRITICAL') {
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/alert-128.png',
      title: '⚠️ BlindEye: Critical Threat Detected',
      message: threat.details,
      priority: 2,
    });
  }

  // Update badge with threat count
  updateBadge(tabId, threatsByTab[tabId].length);
}

function updateBadge(tabId, count) {
  if (!tabId) return;

  chrome.action.setBadgeText({
    tabId: tabId,
    text: count > 0 ? count.toString() : '',
  });

  chrome.action.setBadgeBackgroundColor({
    tabId: tabId,
    color: count > 0 ? '#DC2626' : '#10B981',
  });
}

// Clean up when tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
  delete threatsByTab[tabId];
});

// Reset icon when tab is updated (navigating to new page)
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === 'loading') {
    threatsByTab[tabId] = [];
    chrome.action.setIcon({
      tabId: tabId,
      path: {
        16: 'icons/safe-16.png',
        48: 'icons/safe-48.png',
        128: 'icons/safe-128.png',
      },
    });
    updateBadge(tabId, 0);
  }
});

// Handle popup requests for threat data
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'get_threats') {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tabId = tabs[0]?.id;
      sendResponse({ threats: threatsByTab[tabId] || [] });
    });
    return true; // Keep channel open for async response
  }
});

console.log('[BlindEye] Background service worker initialized');
