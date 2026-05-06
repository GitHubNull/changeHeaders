# changeHeaders 详细使用教程

本文档提供changeHeaders插件的完整使用指南，包括安装、配置和高级用法。

## 目录

- [安装指南](#安装指南)
- [界面介绍](#界面介绍)
- [基础操作](#基础操作)
- [高级功能](#高级功能)
- [使用场景](#使用场景)
- [常见问题](#常见问题)

---

## 安装指南

### 环境要求

- **Java**: 8或更高版本
- **Burp Suite**: Professional或Community Edition

### 方法1: 直接安装JAR

1. 从 [GitHub Releases](https://github.com/GitHubNull/changeHeaders/releases) 下载最新的JAR文件
2. 打开Burp Suite
3. 导航到 `Extensions` → `Installed`
4. 点击 `Add`
5. 选择 `Extension type` 为 `Java`
6. 浏览并选择下载的JAR文件
7. 点击 `Next` 完成安装

### 方法2: 从源码构建

```bash
# 克隆仓库
git clone https://github.com/GitHubNull/changeHeaders.git
cd changeHeaders

# 使用Maven构建（标准构建）
mvn clean package

# 使用Maven构建（带时间戳的调试构建）
mvn clean package "-Ddebug.build=true"

# JAR文件将在target/目录中生成
```

> **提示**: 使用 `-Ddebug.build=true` 构建时，将生成一个带时间戳的附加JAR文件，便于区分不同构建版本。

---

## 界面介绍

安装后，Burp Suite中将出现 `changeHeaders` 标签页。

### 主界面布局

![TabUI主界面](../img/tabUI.png)

界面分为以下几个区域：

#### 1. 模块选择区
勾选需要应用请求头修改的Burp Suite模块：
- **Proxy**: 代理模块
- **Repeater**: 重放模块
- **Intruder**: 入侵模块
- **Scanner**: 扫描模块
- **Extender**: 扩展模块

#### 2. 请求头列表
以表格形式展示所有配置的请求头规则：

| 列名 | 说明 |
|-----|------|
| Enable | 是否启用该规则 |
| Header Name | 请求头名称 |
| Header Value | 请求头值 |
| PopupMenu | 是否启用右键手动替换 |
| Persist | 是否持久化保存 |

#### 3. 功能按钮区
- **Add**: 手动添加新规则
- **Edit**: 编辑选中的规则
- **Delete**: 删除选中的规则
- **从剪贴板导入**: 从剪贴板批量导入请求头
- **导入右键替换头**: 导入已配置的右键替换规则
- **Export**: 导出配置到JSON文件
- **Import**: 从JSON文件导入配置
- **Clear All**: 清除所有配置

#### 4. 语言切换
点击切换中文/英文界面。

---

## 基础操作

### 添加请求头规则

#### 方式1: 手动添加

1. 点击 `Add` 按钮
2. 在弹出的对话框中输入：
   - Header Name: 请求头名称（如 `Authorization`）
   - Header Value: 请求头值（如 `Bearer token123`）
3. 根据需要勾选选项：
   - **Enable**: 启用该规则
   - **PopupMenu**: 启用右键手动替换
   - **Persist**: 持久化保存
4. 点击确定

#### 方式2: 从请求中添加

1. 在任意HTTP请求中选中一行Header文本
2. 右键点击，选择：
   - **新增自动替换头**: 添加为自动应用的规则
   - **新增手动触发替换头**: 添加为右键手动替换的规则

![从请求添加](../img/选择hearer进行鼠标右键菜单更新header的取值.png)

#### 方式3: 从剪贴板导入

1. 复制包含HTTP请求头的文本到剪贴板
2. 点击 `从剪贴板导入` 按钮
3. 在弹出的对话框中勾选需要的请求头
4. 点击确定完成导入

![从剪贴板导入](../img/从剪贴板导入.png)

> **智能识别**: 常见的安全相关请求头（Cookie、Authorization、Token等）会自动勾选。

#### 方式4: 导入右键替换头

1. 点击 `导入右键替换头` 按钮
2. 从已启用PopupMenu的请求头中选择
3. 点击确定导入

![导入右键替换头](../img/导入右键替换头.png)

### 应用请求头

#### 自动应用

1. 确保规则的 `Enable` 列已勾选
2. 勾选需要应用的模块（如Proxy、Repeater）
3. 发送请求时，请求头会自动添加/替换

#### 手动替换

1. 确保规则的 `PopupMenu` 列已勾选
2. 在HTTP编辑器中右键点击
3. 选择 `替换` 菜单下的对应请求头

![右键替换](../img/鼠标右键菜单替换头.png)

### 管理配置

#### 导出配置

1. 点击 `Export` 按钮
2. 选择保存位置
3. 配置将保存为JSON文件

![导出配置](../img/导出配置文件.png)

#### 导入配置

1. 点击 `Import` 按钮
2. 选择之前导出的JSON文件
3. 配置将被加载到列表中

#### 清除配置

点击 `Clear All` 按钮可清除所有配置。

---

## 高级功能

### 两种操作模式

#### 自动模式

- 请求头会自动应用到所有启用的模块
- 适用于需要持续修改请求头的场景
- 配置方法：勾选 `Enable` + 勾选目标模块

#### 手动模式

- 仅在用户主动触发时应用请求头
- 适用于需要精确控制的场景
- 配置方法：勾选 `PopupMenu` + 右键选择替换

### 持久化控制

- **Persist = true**: 请求头会在插件退出/重启后保留
- **Persist = false**: 请求头仅在当前会话有效

> **提示**: 从剪贴板导入的请求头默认不持久化，避免敏感信息被保存。

### 模块特定规则

可以为不同模块配置不同的请求头组合：

1. 创建多个请求头规则
2. 分别勾选不同的目标模块
3. 各模块将只应用其对应的规则

---

## 使用场景

### 场景1: 绕过IP访问控制

```
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
```

将这些Header添加到自动替换列表，测试基于IP的访问控制是否可被绕过。

### 场景2: 用户代理欺骗

```
User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)
```

测试移动端专属功能或绕过UA检测。

### 场景3: 身份验证测试

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
X-API-Key: your-api-key-here
```

快速切换不同的认证凭据进行测试。

### 场景4: 多账户切换

使用手动替换模式，为不同账户配置Cookie：

```
Cookie: session=user1_session_token
Cookie: session=user2_session_token
Cookie: session=admin_session_token
```

通过右键菜单快速切换账户。

---

## 常见问题

### Q: 请求头没有被添加？

**检查项**:
1. 确认规则的 `Enable` 已勾选
2. 确认目标模块已勾选
3. 检查Header名称是否正确（区分大小写）

### Q: 配置丢失了？

**原因**: 可能是 `Persist` 未勾选，或Burp Suite异常退出。

**解决方案**: 
1. 定期导出配置作为备份
2. 重要规则确保勾选 `Persist`

### Q: 手动替换菜单没有出现？

**检查项**:
1. 确认规则的 `PopupMenu` 已勾选
2. 在HTTP编辑器（而非消息查看器）中右键

### Q: 导入配置失败？

**可能原因**:
1. JSON文件格式损坏
2. 版本不兼容

**解决方案**: 检查JSON文件是否有效，或使用最新版本的插件重新导出配置。

---

## 相关文档

- [README](../README.md)
- [测试HTTP服务说明](test-server.md)
- [视频宣传脚本](video-script.md)
