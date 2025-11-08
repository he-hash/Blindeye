// BlindEye Content Script - Monitors DOM for malicious changes

const SENSITIVE_SELECTORS = [
  'input[type="password"]',
  'input[type="email"]',
  'input[name*="password"]',
  'input[name*="email"]',
  'input[name*="credit"]',
  'input[name*="card"]',
  'form[action*="login"]',
  'form[action*="signin"]',
  'form',
];

const SUSPICIOUS_PATTERNS = {
  // Only flag truly unknown domains (whitelist major CDNs and services)
  externalScripts: /https?:\/\/(?!.*(google|gstatic|facebook|twitter|cloudflare|jquery|cdn|jsdelivr|unpkg|cdnjs|googleapis|apple|microsoft|amazon|akamai|fastly|recaptcha))/,
  obfuscation: /(eval|atob|fromCharCode)/,
  dataExfil: /(fetch|XMLHttpRequest|sendBeacon).*\.(password|email|card)/i,
};

// Trusted domains that should never be flagged
const TRUSTED_DOMAINS = [
  'google.com', 'gstatic.com', 'googleapis.com',
  'facebook.com', 'fbcdn.net',
  'twitter.com', 'twimg.com',
  'apple.com', 'cdn-apple.com',
  'cloudflare.com', 'cdnjs.cloudflare.com',
  'jsdelivr.net', 'unpkg.com',
  'jquery.com', 'akamai.net',
  'amazon.com', 'amazonaws.com',
  'microsoft.com', 'live.com',
  'reddit.com', 'redditstatic.com',
  'github.com', 'githubusercontent.com',
];

class BlindEye {
  constructor() {
    this.alerts = [];
    this.observedElements = new Set();
    this.originalAttributes = new WeakMap();
    this.scriptHashes = new Set();
    this.init();
  }

  init() {
    console.log('[BlindEye] Initialized - Monitoring for threats...');
    this.scanInitialDOM();
    this.startMutationObserver();
    this.monitorScriptInjection();
    this.monitorFormSubmissions();
    this.startPeriodicScan();
  }

  // Periodically check for new forms that might have been missed
  startPeriodicScan() {
    setInterval(() => {
      this.trackSensitiveElements();
    }, 2000); // Check every 2 seconds
  }

  // Scan existing DOM on page load
  scanInitialDOM() {
    const scripts = document.querySelectorAll('script');
    scripts.forEach(script => {
      const hash = this.hashScript(script.src || script.textContent);
      this.scriptHashes.add(hash);
    });

    // Track all sensitive elements
    this.trackSensitiveElements();
  }

  trackSensitiveElements() {
    SENSITIVE_SELECTORS.forEach(selector => {
      document.querySelectorAll(selector).forEach(el => {
        if (!this.observedElements.has(el)) {
          this.observedElements.add(el);
          
          // Store original attributes
          const originalAttrs = {};
          if (el.tagName === 'FORM') {
            originalAttrs.action = el.action || el.getAttribute('action');
            originalAttrs.method = el.method;
            originalAttrs.onsubmit = el.onsubmit;
          }
          if (el.tagName === 'INPUT') {
            originalAttrs.type = el.type;
            originalAttrs.name = el.name;
          }
          this.originalAttributes.set(el, originalAttrs);
        }
      });
    });
  }

  // Monitor DOM mutations
  startMutationObserver() {
    const observer = new MutationObserver(mutations => {
      mutations.forEach(mutation => {
        this.handleMutation(mutation);
      });
    });

    observer.observe(document.documentElement, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeOldValue: true,
      characterData: false,
    });
  }

  handleMutation(mutation) {
    // Check for new script injections
    if (mutation.type === 'childList') {
      mutation.addedNodes.forEach(node => {
        if (node.nodeName === 'SCRIPT') {
          this.detectSuspiciousScript(node);
        }
        if (node.querySelectorAll) {
          // Check for new scripts
          node.querySelectorAll('script').forEach(script => {
            this.detectSuspiciousScript(script);
          });
          
          // Track any new sensitive elements (forms, inputs)
          SENSITIVE_SELECTORS.forEach(selector => {
            try {
              node.querySelectorAll(selector).forEach(el => {
                if (!this.observedElements.has(el)) {
                  this.observedElements.add(el);
                  const originalAttrs = {};
                  if (el.tagName === 'FORM') {
                    originalAttrs.action = el.action || el.getAttribute('action');
                    originalAttrs.method = el.method;
                  }
                  if (el.tagName === 'INPUT') {
                    originalAttrs.type = el.type;
                  }
                  this.originalAttributes.set(el, originalAttrs);
                }
              });
            } catch (e) {
              // Selector might not be valid for this node
            }
          });
        }
      });
    }

    // Check for attribute modifications on sensitive elements
    if (mutation.type === 'attributes') {
      const target = mutation.target;
      
      // Make sure we're tracking this element
      if (!this.observedElements.has(target) && this.isSensitiveElement(target)) {
        this.observedElements.add(target);
        const originalAttrs = {};
        if (target.tagName === 'FORM') {
          originalAttrs.action = target.action || target.getAttribute('action');
          originalAttrs.method = target.method;
        }
        if (target.tagName === 'INPUT') {
          originalAttrs.type = target.type;
        }
        this.originalAttributes.set(target, originalAttrs);
        
        // Don't report on first observation
        return;
      }
      
      if (this.isSensitiveElement(target)) {
        this.detectAttributeModification(target, mutation.attributeName, mutation.oldValue);
      }
    }
  }

  detectSuspiciousScript(scriptNode) {
    const src = scriptNode.src;
    const content = scriptNode.textContent;
    const hash = this.hashScript(src || content);

    // Check if this is a new script (not from initial page load)
    if (!this.scriptHashes.has(hash)) {
      // Check if script is from a trusted domain
      if (src && this.isTrustedDomain(src)) {
        this.scriptHashes.add(hash);
        return; // Don't flag trusted domains
      }

      const threat = {
        type: 'SCRIPT_INJECTION',
        severity: 'HIGH',
        element: 'script',
        details: src ? `External script: ${src}` : 'Inline script injection detected',
        timestamp: Date.now(),
      };

      // Check for suspicious patterns only on non-trusted domains
      if (src && SUSPICIOUS_PATTERNS.externalScripts.test(src)) {
        threat.details += ' (Unknown domain)';
        threat.severity = 'CRITICAL';
      }

      if (content && SUSPICIOUS_PATTERNS.obfuscation.test(content)) {
        threat.details += ' (Obfuscated code detected)';
        threat.severity = 'CRITICAL';
      }

      this.reportThreat(threat);
      this.scriptHashes.add(hash);
    }
  }

  isTrustedDomain(url) {
    try {
      const urlObj = new URL(url);
      const hostname = urlObj.hostname.toLowerCase();
      
      return TRUSTED_DOMAINS.some(domain => 
        hostname === domain || hostname.endsWith('.' + domain)
      );
    } catch (e) {
      return false;
    }
  }

  detectAttributeModification(element, attrName, oldValue) {
    const originalData = this.originalAttributes.get(element);
    
    if (attrName === 'action' && element.tagName === 'FORM') {
      const newAction = element.action || element.getAttribute('action');
      const oldAction = originalData?.action;
      
      if (oldAction && newAction && oldAction !== newAction) {
        // Normalize URLs for comparison
        try {
          const oldUrl = new URL(oldAction, window.location.href);
          const newUrl = new URL(newAction, window.location.href);
          
          if (oldUrl.href !== newUrl.href) {
            this.reportThreat({
              type: 'FORM_HIJACK',
              severity: 'CRITICAL',
              element: 'form',
              details: `Form action changed from "${oldUrl.href}" to "${newUrl.href}"`,
              timestamp: Date.now(),
            });
          }
        } catch (e) {
          // If URL parsing fails, still report it
          this.reportThreat({
            type: 'FORM_HIJACK',
            severity: 'CRITICAL',
            element: 'form',
            details: `Form action changed from "${oldAction}" to "${newAction}"`,
            timestamp: Date.now(),
          });
        }
      }
    }

    if (attrName === 'type' && element.tagName === 'INPUT') {
      if (oldValue === 'password' && element.type !== 'password') {
        this.reportThreat({
          type: 'INPUT_MODIFICATION',
          severity: 'HIGH',
          element: 'input',
          details: 'Password input type was modified',
          timestamp: Date.now(),
        });
      }
    }

    // Check for suspicious event handlers
    if (attrName && attrName.startsWith('on')) {
      this.reportThreat({
        type: 'EVENT_HANDLER_INJECTION',
        severity: 'HIGH',
        element: element.tagName.toLowerCase(),
        details: `Suspicious event handler added: ${attrName}`,
        timestamp: Date.now(),
      });
    }
  }

  isSensitiveElement(element) {
    return SENSITIVE_SELECTORS.some(selector => {
      try {
        return element.matches && element.matches(selector);
      } catch (e) {
        return false;
      }
    });
  }

  monitorScriptInjection() {
    // Override eval to detect usage
    const originalEval = window.eval;
    window.eval = function(...args) {
      console.warn('[BlindEye] eval() usage detected');
      return originalEval.apply(this, args);
    };
  }

  monitorFormSubmissions() {
    document.addEventListener('submit', (e) => {
      const form = e.target;
      if (form.tagName === 'FORM') {
        const originalData = this.originalAttributes.get(form);
        if (originalData && originalData.action && form.action !== originalData.action) {
          e.preventDefault();
          this.reportThreat({
            type: 'FORM_SUBMISSION_BLOCKED',
            severity: 'CRITICAL',
            element: 'form',
            details: 'Form submission blocked - action was modified',
            timestamp: Date.now(),
          });
        }
      }
    }, true);
  }

  reportThreat(threat) {
    console.warn('[BlindEye] THREAT DETECTED:', threat);
    this.alerts.push(threat);

    // Send to background script
    chrome.runtime.sendMessage({
      action: 'threat_detected',
      threat: threat,
      url: window.location.href,
    });

    // Update badge
    chrome.runtime.sendMessage({
      action: 'update_badge',
      count: this.alerts.length,
    });
  }

  hashScript(content) {
    if (!content) return 'empty';
    let hash = 0;
    for (let i = 0; i < content.length; i++) {
      const char = content.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return hash.toString();
  }
}

// Initialize BlindEye
const blindEye = new BlindEye();

// Listen for messages from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'get_alerts') {
    sendResponse({ alerts: blindEye.alerts });
  }
});
