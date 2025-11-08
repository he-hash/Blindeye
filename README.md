# BlindEye - Malicious Content Injection Detector

<div align="center">

![BlindEye Logo](icons/safe-128.png)

**A Chrome extension that monitors DOM changes in real-time and warns when unknown scripts modify sensitive HTML elements**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Chrome Web Store](https://img.shields.io/badge/Chrome-Extension-blue.svg)](https://chrome.google.com/webstore)

</div>

## Overview

BlindEye is a browser-based Endpoint Detection and Response (EDR) tool that acts as your personal security guard against malicious content injection attacks. It continuously monitors your browsing session for suspicious activities like:

- **Script Injection** - Detects when new, unknown scripts are added to the page
- **Form Hijacking** - Alerts when login or payment forms are tampered with
- **Event Handler Injection** - Identifies suspicious event listeners being attached
- **Input Modification** - Warns when sensitive input fields are altered
- **Real-time Monitoring** - Uses MutationObserver for zero-delay detection

## Features

### Core Protection
- **Real-time DOM Monitoring** - Tracks all changes to the page structure
- **Sensitive Element Protection** - Focuses on login forms, password fields, and payment inputs
- **Script Analysis** - Identifies obfuscated code and suspicious patterns
- **Form Hijacking Prevention** - Blocks form submissions if the action URL has been modified
- **Visual Alerts** - Red icon indicator when threats are detected
- **Threat Dashboard** - Beautiful popup interface showing all detected threats

### Security Capabilities
- Detects external script injections from unknown domains
- Identifies obfuscation techniques (eval, atob, fromCharCode)
- Monitors for data exfiltration attempts
- Tracks attribute modifications on sensitive elements
- Prevents hijacked form submissions
- Maintains original element state for comparison

## Installation

### For Development & Testing

1. **Clone or Download** this repository:
```bash
git clone https://github.com/he-hash/blindeye.git
cd blindeye
```

2. **Open Chrome Extensions Page**:
   - Navigate to `chrome://extensions/`
   - Or click the three dots menu → More Tools → Extensions

3. **Enable Developer Mode**:
   - Toggle the "Developer mode" switch in the top-right corner

4. **Load the Extension**:
   - Click "Load unpacked"
   - Select the `blindeye` folder
   - The extension should now appear in your extensions list

5. **Pin the Extension**:
   - Click the puzzle icon in Chrome toolbar
   - Find BlindEye and click the pin icon
   - The BlindEye icon will now be visible in your toolbar

### For Usage 

See the extension in the chrome store here : 

## Usage

### Basic Usage

1. **Browse Normally** - BlindEye runs automatically on all websites
2. **Watch the Icon** - The icon changes from green (safe) to red (alert) when threats are detected
3. **View Threats** - Click the extension icon to see the threat dashboard
4. **Review Details** - Each threat shows:
   - Threat type and severity
   - Element affected
   - Detailed description
   - Timestamp

### Understanding Threat Levels

- **CRITICAL** - Immediate action required (form hijacking, malicious scripts)
- **HIGH** - Significant concern (unknown script injection, suspicious modifications)
- **MEDIUM** - Potential issue (minor modifications, unknown patterns)

### Dashboard Features

- **Threat Count** - Total number of threats detected on current page
- **Elements Monitored** - Estimated count of protected elements
- **Threat History** - Chronological list of all detected threats
- **Clear History** - Reset the threat counter and clear alerts
- **Refresh** - Manually refresh threat data

## Project Structure

```
blindeye/
├── manifest.json           # Extension configuration
├── content.js             # DOM monitoring and threat detection
├── background.js          # Service worker for threat management
├── popup.html            # Dashboard UI structure
├── popup.css             # Dashboard styling
├── popup.js              # Dashboard functionality
├── icons/                # Extension icons
│   ├── safe-16.png      # Green (safe) state - 16x16
│   ├── safe-48.png      # Green (safe) state - 48x48
│   ├── safe-128.png     # Green (safe) state - 128x128
│   ├── alert-16.png     # Red (alert) state - 16x16
│   ├── alert-48.png     # Red (alert) state - 48x48
│   └── alert-128.png    # Red (alert) state - 128x128
└── README.md            # This file
```

## Technical Details

### Technologies Used

- **Manifest V3** - Latest Chrome extension standard
- **MutationObserver API** - Real-time DOM change detection
- **Chrome Extension APIs**:
  - `chrome.runtime` - Message passing
  - `chrome.tabs` - Tab management
  - `chrome.action` - Icon and badge updates
  - `chrome.notifications` - Alert notifications
  - `chrome.storage` - Data persistence

### Detection Methods

1. **Script Hash Tracking** - Maintains hashes of initial scripts to detect new injections
2. **Attribute Monitoring** - Stores original attributes of sensitive elements
3. **Pattern Matching** - Uses regex to identify suspicious code patterns
4. **Event Handler Analysis** - Detects dynamically added event listeners
5. **Form Action Validation** - Compares current form actions with original values

### Performance

- **Minimal Overhead** - Efficient mutation observer implementation
- **Lazy Initialization** - Only monitors when needed
- **Optimized Queries** - Targeted DOM selections
- **Memory Efficient** - WeakMap usage for element tracking


## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request



## Support

- **Issues**: [GitHub Issues](https://github.com/he-hash/blindeye/issues)
- **Documentation**: This README

## 🔮 Future Enhancements

- [ ] Custom whitelist/blacklist domains
- [ ] Export threat reports
- [ ] Integration with security APIs
- [ ] Machine learning threat detection
- [ ] Cross-browser support (Firefox, Edge)
- [ ] Advanced configuration options
- [ ] Threat statistics dashboard

---

<div align="center">

**Made with 🛡️ for a safer web**

[Report Bug](https://github.com/he-hash/blindeye/issues) · [Request Feature](https://github.com/he-hash/blindeye/issues) · [View Demo](#)

</div>
