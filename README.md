# changeHeaders 项目

## 简介

`changeHeaders` 是一个用于修改 HTTP 请求头的工具，旨在帮助开发人员和安全研究人员测试和调试 HTTP 请求。该项目基于 Java 开发，并集成了 Burp Suite 的扩展 API 和 Fastjson2 库。

## 目录结构
```commandline
├── src 
│ ├── main 
│ │ ├── java 
│ │ └── resources 
│ └── test 
│ └── java 
├── target 
├── pom.xml 
└── README.md
```
## 安装

### 前提条件

- Java 8 或更高版本
- Maven 3.5 或更高版本

### 构建项目

1. 克隆仓库：
 ```bash
git clone https://github.com/your-repo/changeHeaders.git
cd changeHeaders
```

2. 使用 Maven 构建项目
```bash
mvn clean package 
```

这将生成一个可执行的 JAR 文件，位于 `target` 目录下。

### 插件安装

#### 方法一：通过 Burp Suite 加载本地 JAR 文件

1. 打开 Burp Suite。
2. 导航到 `Extender` -> `Extensions`。
3. 点击 `Add` 按钮。
4. 选择 `Extension type` 为 `Java`。
5. 浏览并选择构建生成的 JAR 文件（例如 `target/changeHeaders-1.6.0.jar`）。
6. 点击 `Next` 并完成加载。

#### 方法二：通过 GitHub Releases 下载预编译的 JAR 文件

1. 访问 [GitHub Releases 页面](https://github.com/your-repo/changeHeaders/releases)。
2. 下载最新的 JAR 文件（例如 `changeHeaders-1.6.0.jar`）。
3. 打开 Burp Suite。
4. 导航到 `Extender` -> `Extensions`。
5. 点击 `Add` 按钮。
6. 选择 `Extension type` 为 `Java`。
7. 浏览并选择下载的 JAR 文件。
8. 点击 `Next` 并完成加载。

## 使用方法

### 运行工具

1. **加载插件**：
    - 确保你已经按照 [安装](#插件安装) 部分的说明成功加载了 `changeHeaders` 插件到 Burp Suite。

2. **配置生效模块**：
    - 在 Burp Suite 的主界面中，你会看到一个名为 `changeHeaders` 的新标签页。
    - 点击该标签页进入配置界面。
    - 在顶部的“生效模块”区域，勾选你希望 `changeHeaders` 生效的 Burp Suite 模块（例如：Proxy、Repeater、Intruder、Scanner、Extender）。你可以通过勾选或取消勾选相应的复选框来启用或禁用这些模块中的请求头修改功能。

3. **添加和管理请求头**：
    - 在中间的表格区域，你可以查看和管理已配置的 HTTP 请求头。
    - 点击“新增”按钮，可以添加新的请求头条目。默认情况下，会添加一条包含“键”、“值”、“描述”等字段的新记录。
    - 选择一行或多行记录后，点击“删除”按钮可以移除选中的请求头条目。
    - 如果需要清除所有配置，点击“清除所有配置”按钮，这将重置所有设置，并清空表格中的所有条目。

4. **发送和修改请求**：
    - 在 Burp Suite 的 `Proxy` 或 `Repeater` 模块中，右键点击你想要修改的 HTTP 请求。
    - 选择 `Send to changeHeaders` 选项，这将把选中的请求发送到 `changeHeaders` 界面。
    - 在 `changeHeaders` 界面中，你可以根据需要修改 HTTP 请求头，并点击“发送”按钮以应用更改并发送修改后的请求。

5. **保存配置**：
    - 所有在 `changeHeaders` 界面中进行的配置都会自动保存，无需手动操作。
    - 如果你需要导出或备份配置，可以通过 Burp Suite 的扩展管理功能进行操作。

### 示例

假设你正在测试一个 Web 应用程序，并希望通过 `changeHeaders` 修改某些请求头以绕过安全检查。你可以按照以下步骤操作：

1. 在 Burp Suite 中拦截一个 HTTP 请求。
2. 右键点击该请求并选择 `Send to changeHeaders`。
3. 在 `changeHeaders` 界面中，勾选 `Proxy` 和 `Repeater` 模块。
4. 添加一个新的请求头，例如 `X-Forwarded-For: 192.168.1.1`。
5. 点击“发送”按钮，观察应用程序对修改后的请求的响应。

## 贡献

欢迎贡献代码！请遵循以下步骤：

1. Fork 本仓库。
2. 创建一个新的分支 (`git checkout -b feature-branch`)。
3. 提交你的更改 (`git commit -am 'Add some feature'`)。
4. 推送到分支 (`git push origin feature-branch`)。
5. 发起 Pull Request。

## 许可证

本项目采用 [MIT License](LICENSE) 许可证。详情请参见 `LICENSE` 文件。

## 联系方式

如果你有任何问题或建议，请通过 [GitHub Issues](https://github.com/GitHubNull/changeHeaders/issues) 或邮件联系作者。

---