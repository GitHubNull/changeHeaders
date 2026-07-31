# 变更日志 (Changelog)

本文档记录 changeHeaders 项目的所有重要变更。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

---

## [3.4.0] - 2026-07-31 21:38:00

### 新增
- **Last-Modified 字段本地化**：新增"响应头管理"下的 Last-Modified 子标签页，支持解析 RFC1123 / RFC850 / asctime 格式原始 Last-Modified，保持时间点不变换算到目标时区后按选定格式输出
- **双格式模式**：Last-Modified 支持 HTTP 兼容（RFC1123）与自定义 pattern，自定义模式下随插件语言环境本地化（中/英星期、月份等），实时预览渲染效果
- **缺失补充偏移**：响应缺失 Last-Modified 时可按"当前时间 + 可配置偏移分钟数"（默认 0，允许负值构造过去修改时刻）自动补充
- **修改时刻保护**：对无法解析的原始取值一律原样保留，避免虚构资源修改时刻破坏条件请求与缓存协商
- **国际化**：Last-Modified 相关全部文案支持中英文切换（messages / messages_en / messages_zh / messages_zh_CN 四份资源同步）

### 变更
- **处理器复用**：`LastModifiedHeaderHandler` 复用 `AbstractHttpDateHeaderHandler`、`LastModifiedHeaderPanel` 复用 `HttpDateHeaderPanel`，与 Date / Expires 结构完全一致
- **持久化扩展**：`responseHeaderConfig` 节点新增 `lastModified*` 字段，向后兼容旧版无该字段的配置文件

---

## [3.3.0] - 2026-07-31 20:48:32

### 新增
- **Expires 字段本地化**：新增"响应头管理"下的 Expires 子标签页，支持解析 RFC1123 / RFC850 / asctime 格式原始 Expires，保持时间点不变换算到目标时区后按选定格式输出
- **双格式模式**：Expires 同样支持 HTTP 兼容（RFC1123）与自定义 pattern，自定义模式下随插件语言环境本地化（中/英星期、月份等），实时预览当前时间渲染效果
- **缺失补充偏移**：响应缺失 Expires 时可按"当前时间 + 可配置偏移分钟数"（默认 60，允许负值构造已过期时刻）自动补充
- **过期语义保护**：对 `0`、`-1` 等纯数字标记以及无法解析的取值一律原样保留，避免破坏缓存语义
- **国际化**：Expires 相关全部文案支持中英文切换（messages / messages_en / messages_zh / messages_zh_CN 四份资源同步）

### 变更
- **处理器架构重构**：抽取 `AbstractHttpDateHeaderHandler` 基类与 `HttpDateHeaderPanel` UI 基类，Date 与 Expires 共享解析、时区换算、格式化与单次错误日志逻辑，各自保留独立的启用/格式/时区/补充配置
- **持久化扩展**：`responseHeaderConfig` 节点新增 `expires*` 字段，向后兼容旧版无该字段的配置文件

---

## [3.2.0] - 2026-07-31

### 新增
- **响应头管理标签页**：新增第二个标签页"响应头管理"，通过可扩展的 handler 注册表 + 不可变配置快照实现响应头改写框架
- **Date 字段时区换算**：支持解析 RFC1123 / RFC850 / asctime 格式原始 Date，保持时间点不变换算到目标时区后按选定格式输出
- **双格式模式**：HTTP 兼容（RFC1123）与自定义 pattern 两种输出模式可切换，实时预览当前时间渲染效果
- **独立生效范围**：响应头工具勾选（proxy/repeater/intruder/scanner/extender）与请求头 `TOOL_FLAGS` 完全隔离
- **缺失补充**：支持响应中无 Date 时自动追加当前时间（可选开关）
- **国际化**：响应头管理页全部文案支持中英文切换
- **持久化**：响应头配置以 `responseHeaderConfig` 节点写入 YAML，向后兼容旧版无该节点的配置文件

---

## [3.1.1] - 2026-05-08

### 新增
- 新增变更日志文档 `doc/CHANGELOG.md`，记录项目版本变更历史
- README 和 README_en 中添加变更日志链接入口

## [3.1.0] - 2026-05-07

### 新增
- 搜索过滤功能，支持按关键字快速筛选 Header 规则
- 弹窗编辑功能，优化 Header 条目的编辑体验

## [3.0.0] - 2026-05-07

### 变更
- **破坏性变更**：配置序列化从 Fastjson2/JSON 迁移至 SnakeYAML/YAML
- 配置文件格式由 JSON 变更为 YAML，旧版配置需重新导入

## [2.5.0] - 2026-05-07

### 新增
- 全选/全取消按钮，支持批量启用或禁用所有 Header 规则
- 偏好自动勾选功能
- 数据变更监听机制，偏好数据变更时自动同步 UI

### 修复
- 移除未使用的重载方法

## [2.4.0] - 2026-05-06

### 新增
- 消除硬编码版本号，改用 Maven 资源过滤动态管理版本号

## [2.3.2] - 2026-05-06

### 新增
- 添加 `importPopupMenuHeaders` 国际化键，支持右键菜单导入按钮的多语言显示

## [2.3.1] - 2026-05-06

### 修复
- 清理死代码和多余注解
- 修复返回值类型及 key 合并逻辑错误

## [2.3.0] - 2026-01-06

### 新增
- 内置测试 HTTP 服务，提供多种请求头验证端点
- 更新 GitHub Actions 发布流程

## [2.2.0] - 2026-01-06

### 修复
- 修复 `addHeaderItem` 和 `updateHeaderItem` 的索引越界问题
- 修复删除操作后 keyMap 索引不同步导致的 `IndexOutOfBoundsException`
- 修复多行删除时索引错误的问题

### 新增
- 添加多个界面相关的截图资源
- 更新 README 文档添加功能截图

## [2.1.0] - 2026-01-06

### 修复
- 配置 Maven 仓库镜像解决 GitHub Actions 构建失败问题

## [2.0.0] - 2025-08-04

### 新增
- 剪贴板导入功能，支持从剪贴板批量导入 Header 规则
- 优化持久化控制机制

### 变更
- **破坏性变更**：新增剪贴板导入功能，持久化控制逻辑重构

## [1.9.0] - 2025-08-01

### 新增
- 国际化支持，中英双语切换
- GitHub Actions 自动发布流程
- 配置文件导入导出功能
- 手动替换 Headers 功能（右键菜单触发）
- 每行 Header 规则独立启用/禁用控制

### 修复
- 修复更新 HeaderItem 时未设置 `popupMenuEnable` 的问题

### 变更
- 优化项目构建配置，添加调试构建功能
- 更新项目文档并添加英文版本

---

## 早期版本 (Pre-1.9.0)

以下版本在引入 Git Tag 之前开发，日期基于提交记录。

### [0.x] - 2024-07 ~ 2025-06

#### 2025-06-24
- 优化配置加载和表格数据刷新性能

#### 2025-05-19
- 更新项目 JDK 版本并添加构建工件

#### 2024-12-25
- 重构代码并添加新功能
- 优化 HeaderItemTableModel 类结构
- 优化右键菜单显示文案
- 修复 Flyway 版本初始化问题
- 排除 fastjson2 依赖

#### 2024-12-10
- 添加 HeaderItem 模型类

#### 2024-12-04
- 添加 EXTENDER 工具支持并优化 UI 功能

#### 2024-07-29
- 项目初始版本发布

---

[3.2.0]: https://github.com/GitHubNull/changeHeaders/releases/tag/v3.2.0
[3.1.1]: https://github.com/GitHubNull/changeHeaders/releases/tag/v3.1.1
[3.1.0]: https://github.com/GitHubNull/changeHeaders/releases/tag/v3.1.0
[3.0.0]: https://github.com/GitHubNull/changeHeaders/releases/tag/v3.0.0
[2.5.0]: https://github.com/GitHubNull/changeHeaders/releases/tag/v2.5.0
[2.4.0]: https://github.com/GitHubNull/changeHeaders/releases/tag/v2.4.0
[2.3.2]: https://github.com/GitHubNull/changeHeaders/releases/tag/v2.3.2
[2.3.1]: https://github.com/GitHubNull/changeHeaders/releases/tag/v2.3.1
[2.3.0]: https://github.com/GitHubNull/changeHeaders/releases/tag/v2.3.0
[2.2.0]: https://github.com/GitHubNull/changeHeaders/releases/tag/v2.2.0
[2.1.0]: https://github.com/GitHubNull/changeHeaders/releases/tag/v2.1.0
[2.0.0]: https://github.com/GitHubNull/changeHeaders/releases/tag/v2.0.0
[1.9.0]: https://github.com/GitHubNull/changeHeaders/releases/tag/v1.9.0
