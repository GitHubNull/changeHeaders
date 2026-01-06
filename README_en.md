# changeHeaders - Advanced HTTP Header Manipulation Tool

[![Java](https://img.shields.io/badge/Java-8+-blue.svg)](https://www.oracle.com/java/technologies/)
[![Burp Suite](https://img.shields.io/badge/Burp%20Suite-Extension-orange.svg)](https://portswigger.net/burp)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

[中文版本](README.md)

## 🌟 Overview

changeHeaders is a powerful Burp Suite extension that allows security professionals and developers to easily modify HTTP request headers. Whether you're performing penetration testing, bug bounty hunting, or application debugging, changeHeaders streamlines the process of header manipulation across multiple Burp Suite tools.

With an intuitive GUI and robust configuration management, changeHeaders helps you:
- Bypass security restrictions by adding/modifying security headers
- Test application behavior with different user agents or referrers
- Simulate requests from different sources or devices
- Automate repetitive header modification tasks

## ✨ Key Features

### 🔧 Powerful Header Management
- **Add/Modify/Delete Headers**: Easily manage HTTP request headers with a user-friendly table interface
- **Bulk Operations**: Apply multiple header changes simultaneously across different tools
- **Enable/Disable Rules**: Toggle header modifications on-the-fly without deleting configurations

### 🎯 Multi-Tool Integration
- Works seamlessly with all major Burp Suite tools:
  - Proxy
  - Repeater
  - Intruder
  - Scanner
  - Extender
- Context menu integration for quick access to header modification interface

### 💾 Smart Configuration Management
- **Auto-Save**: All configurations are automatically saved and persist between sessions
- **Import/Export**: Easily share configurations between team members or projects using JSON format
- **Selective Application**: Choose which Burp tools should apply your header modifications

### 🌍 Internationalization
- **Multi-Language Support**: Available in both English and Chinese
- **Easy Language Switching**: Toggle between languages with a single click

### 🛠 Advanced Features
- **Module-Specific Rules**: Apply different headers to different Burp Suite modules
- **Real-time Preview**: See header changes before sending requests
- **Persistent Storage**: Configurations automatically saved using Burp's extension settings
- **Right-Click Context Menu Integration**: 
  - **Auto Replace**: Automatically add/update headers from selected request text
  - **Manual Trigger Replace**: Add headers that can be manually applied to requests via context menu
  - **Active Header Replacement**: Apply selected headers directly to the current request in the HTTP editor

### 🔄 Two Modes of Operation
1. **Automatic Mode**: Headers are automatically applied to requests based on module settings
2. **Manual Mode**: Headers are applied only when manually triggered via context menu

### 📋 New Feature Highlights
- **Clipboard Import**: One-click import of HTTP headers from system clipboard, automatically parsed and let users choose which headers to add
- **Smart Default Selection**: Common security-related headers (such as Cookie, Authorization, Token, etc.) are automatically selected by default
- **Persistence Control**: Control whether each header is saved when the plugin is unloaded or exited. Headers imported from clipboard are not persistent by default
- **Selective Persistence**: When exporting configuration or exiting the plugin, only headers marked as persistent are saved
- **Popup Menu Header Import**: Import headers with popup menu enabled (popupMenuEnable) from a dialog window accessed via a button below the table, facilitating quick copying and management of commonly used manual replacement rules

## 📋 Installation

### Prerequisites
- Java 8 or higher
- Burp Suite Professional or Community Edition

### Installation Methods

#### Method 1: Direct JAR Installation
1. Download the latest release JAR file from [GitHub Releases](https://github.com/your-repo/changeHeaders/releases)
2. Open Burp Suite
3. Navigate to `Extensions` → `Installed`
4. Click `Add`
5. Select `Extension type` as `Java`
6. Browse and select the downloaded JAR file
7. Click `Next` to complete installation

#### Method 2: Build from Source
```bash
# Clone the repository
git clone https://github.com/your-repo/changeHeaders.git
cd changeHeaders

# Build with Maven (standard build)
mvn clean package

# Build with Maven (debug build with timestamp)
mvn clean package "-Ddebug.build=true"

# The JAR file will be generated in the target/ directory
```

**Note**: When building with `-Ddebug.build=true`, an additional JAR file with a timestamp will be generated (e.g., `changeHeaders-1.9.0-20250801170300.jar`). This is useful for distinguishing between different build versions during development and debugging.

## 🚀 Quick Start Guide

### 1. Configure Target Modules
After installation, a new `changeHeaders_v1.9.0` tab will appear in Burp Suite:
- Select which Burp Suite modules should apply your header modifications
- Available modules: Proxy, Repeater, Intruder, Scanner, Extender
- Enable "popupMenu" for manual header application via context menu

### 2. Add Header Rules
Four methods to add header rules:
1. **Manual Addition**: Click `Add` in the main interface to create new header rules
2. **From Request**: Select header text in any HTTP request and right-click to choose "新增自动替换头" or "新增手动触发替换头"
3. **From Clipboard**: Click the "Import from Clipboard" button to automatically parse HTTP headers from the clipboard and let users choose which headers to add
4. **Import Popup Menu Headers**: Click the "Import Popup Menu Headers" button to select and import headers that have popupMenu enabled, making it easy to reuse manual trigger replacement rules

### 3. Apply Headers to Requests
Three methods to apply header modifications:
1. **Automatic Application**: When enabled modules process requests, headers are automatically applied
2. **Right-click Method**: In any Burp tool, right-click a request and select `Send to changeHeaders`
3. **Context Menu Application**: For headers with "popupMenu" enabled, right-click in the HTTP editor and select "替换" to apply headers directly

### 4. Manage Configurations
- **Export**: Save your header configurations to a JSON file for backup or sharing
- **Import**: Load previously saved configurations
- **Clear**: Remove all configurations with a single click

## 🎯 Use Cases

### Security Testing
```
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
```
Bypass IP-based access controls by spoofing internal IP addresses.

### User-Agent Spoofing
```
User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)
```
Test mobile versions of applications or bypass browser-specific restrictions.

### Authentication Testing
```
Authorization: Bearer <token>
X-API-Key: <key>
```
Quickly switch between different authentication tokens or API keys.

### Context Menu Usage
1. **Auto Replace Headers**:
   - Select header lines in any HTTP request
   - Right-click and choose "新增自动替换头"
   - Headers will be automatically applied to all requests in enabled modules

2. **Manual Trigger Replace**:
   - Select header lines in any HTTP request
   - Right-click and choose "新增手动触发替换头"
   - Enable "popupMenu" for these headers in the main interface
   - Right-click in any HTTP editor and select "替换" to apply these headers

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

Please ensure your code follows the existing style and includes appropriate tests.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📞 Support

- For bug reports and feature requests, please use [GitHub Issues](https://github.com/your-repo/changeHeaders/issues)
- For general questions, check the documentation or contact the maintainers

## 🙏 Acknowledgments

- Thanks to the Burp Suite team for providing an excellent platform for security testing
- Inspired by the need for more efficient HTTP header manipulation in web application testing

## ⚠️ Disclaimer

This tool is intended for legitimate security testing and research purposes only. Users are responsible for ensuring their use complies with all applicable laws and regulations. The author is not liable for any damages or legal consequences resulting from the use of this tool. Before using this tool for any testing, ensure you have explicit authorization from the owners of the target systems. Unauthorized system access may violate laws.

By using this tool, you agree that:
1. You will only use this tool on systems for which you have explicit authorization
2. You will comply with all applicable local, state, and federal laws
3. You understand that improper use may result in legal consequences
4. The author is not responsible for misuse of the tool or any resulting damages
5. When using this tool in a corporate or organizational environment, you will adhere to that organization's security policies and regulations