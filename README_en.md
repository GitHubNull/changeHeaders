# changeHeaders - Advanced HTTP Header Manipulation Tool

[![Java](https://img.shields.io/badge/Java-8+-blue.svg)](https://www.oracle.com/java/technologies/)
[![Burp Suite](https://img.shields.io/badge/Burp%20Suite-Extension-orange.svg)](https://portswigger.net/burp)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

[中文版](README.md) | [Usage Guide](doc/usage-guide.md) | [Video Script](doc/video-script.md)

## 🌟 Overview

changeHeaders is a powerful Burp Suite extension that allows security professionals and developers to easily modify HTTP request headers.

With an intuitive GUI and powerful configuration management, changeHeaders helps you:
- Bypass security restrictions by adding/modifying security headers
- Test application behavior with different user agents or referrers
- Simulate requests from different sources or devices
- Automate repetitive header modification tasks

## ✨ Key Features

| Feature | Description |
|---------|-------------|
| 🔧 Header Management | Add/modify/delete headers, batch operations, dynamic toggle |
| 🎯 Multi-tool Integration | Proxy, Repeater, Intruder, Scanner, Extender support |
| 💾 Config Management | Auto-save, JSON import/export, selective application |
| 🌍 Internationalization | Chinese and English support |
| 🔄 Dual Mode | Auto mode + Manual replace mode |
| 📋 Smart Import | Clipboard parsing, right-click quick add |

## 📋 Quick Installation

### Requirements
- Java 8+
- Burp Suite Professional/Community

### Installation Steps
1. Download JAR from [GitHub Releases](https://github.com/GitHubNull/changeHeaders/releases)
2. Burp Suite → Extensions → Installed → Add
3. Select Java type, load the JAR file

> For detailed installation, see [Usage Guide](doc/usage-guide.md#installation-guide)

## 🚀 Quick Start

### 1. Configure Modules
After installation, check the modules (Proxy, Repeater, etc.) in the changeHeaders tab.

![TabUI Interface](img/tabUI.png)

### 2. Add Rules

Four ways to add header rules:

| Method | Description |
|--------|-------------|
| Manual Add | Click Add button, enter header name and value |
| Right-click Add | Select header in request, right-click to add |
| Clipboard Import | Batch import with auto-parsing |
| Import Replace Rules | Reuse existing right-click rules |

### 3. Apply Headers

- **Auto Mode**: Rules automatically applied to all requests
- **Manual Mode**: Right-click "Replace" in HTTP editor

> For complete tutorial, see [Usage Guide](doc/usage-guide.md)

## 🎯 Use Cases

```bash
# IP Bypass
X-Forwarded-For: 127.0.0.1

# UA Spoofing
User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)

# Auth Testing
Authorization: Bearer <token>
```

## 🧪 Test HTTP Service

Built-in test service with multiple header validation endpoints:

```bash
cd onlineStore
python server.py
# Visit http://127.0.0.1:8888
```

| Endpoint | Required Header |
|----------|----------------|
| `/api/auth/bearer` | Authorization: Bearer xxx |
| `/api/auth/basic` | Basic Auth (admin:password123) |
| `/api/session/required` | Cookie: session=abc123xyz789 |
| `/api/ip/internal-only` | X-Forwarded-For: 192.168.x.x |

> For full API list, see [Test Server Documentation](doc/test-server.md)

## 📚 Documentation

- [Usage Guide](doc/usage-guide.md) - Complete installation and usage guide
- [Test Server Documentation](doc/test-server.md) - Test HTTP service details
- [Video Script](doc/video-script.md) - Video production reference

## 🤝 Contributing

Contributions are welcome!

1. Fork the repository
2. Create feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

MIT License - See [LICENSE](LICENSE) for details

## 📞 Support

- [GitHub Issues](https://github.com/GitHubNull/changeHeaders/issues) - Bug reports
- [Releases](https://github.com/GitHubNull/changeHeaders/releases) - Downloads

## ⚠️ Disclaimer

This tool is intended for legitimate security testing and research purposes only. Ensure you have explicit authorization before testing any system.
