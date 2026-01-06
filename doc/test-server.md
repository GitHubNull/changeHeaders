# changeHeaders 测试HTTP服务

本文档详细介绍changeHeaders项目内置的测试HTTP服务，用于验证插件的各项功能。

## 概述

测试服务位于 `onlineStore/` 目录，是一个基于Python的轻量级HTTP服务器，提供多种需要特定请求头才能访问的API端点。

## 快速开始

### 启动服务

```bash
# 进入测试服务目录
cd onlineStore

# 启动服务
python server.py

# 或者在Windows上双击
start.bat
```

服务默认运行在 http://127.0.0.1:8888

### 访问测试界面

打开浏览器访问 http://127.0.0.1:8888 即可看到测试界面。

---

## 项目结构

```
onlineStore/
├── server.py           # HTTP服务器主程序
├── config.py           # 配置文件
├── logger.py           # 日志配置
├── start.bat           # Windows启动脚本
├── handlers/           # API处理器模块
│   ├── __init__.py     # 路由配置
│   ├── base.py         # 基础处理器
│   ├── auth.py         # 认证相关API
│   ├── session.py      # Cookie/Session API
│   ├── ip.py           # IP伪造验证API
│   ├── ua.py           # User-Agent API
│   ├── headers.py      # 自定义头API
│   └── composite.py    # 综合验证API
├── static/
│   ├── css/style.css   # 样式文件
│   └── js/app.js       # 前端脚本
└── index.html          # 测试界面
```

---

## API端点详解

### 认证类 (Auth)

#### Bearer Token 验证

```
GET /api/auth/bearer
```

**必需请求头**:
```
Authorization: Bearer any-token-value
```

**验证逻辑**: 检查Authorization头是否以"Bearer "开头，且Token不为空。

**测试示例**:
```bash
# 失败
curl http://127.0.0.1:8888/api/auth/bearer

# 成功
curl -H "Authorization: Bearer my-test-token" http://127.0.0.1:8888/api/auth/bearer
```

---

#### Basic Auth 验证

```
GET /api/auth/basic
```

**必需请求头**:
```
Authorization: Basic YWRtaW46cGFzc3dvcmQxMjM=
```

**验证逻辑**: 解码Base64后验证用户名密码是否为 `admin:password123`。

**测试示例**:
```bash
# 生成Basic认证头
echo -n "admin:password123" | base64
# 输出: YWRtaW46cGFzc3dvcmQxMjM=

# 成功
curl -H "Authorization: Basic YWRtaW46cGFzc3dvcmQxMjM=" http://127.0.0.1:8888/api/auth/basic
```

---

#### API Key 验证

```
GET /api/auth/api-key
```

**必需请求头**:
```
X-API-Key: test-api-key-12345
```

**验证逻辑**: 检查X-API-Key是否等于预设值。

---

### Cookie/Session类

#### Session验证

```
GET /api/session/required
```

**必需请求头**:
```
Cookie: session=abc123xyz789
```

**验证逻辑**: 检查Cookie中是否包含名为session的值，且值为`abc123xyz789`。

---

#### 多Cookie验证

```
GET /api/session/multi-cookie
```

**必需请求头**:
```
Cookie: session=abc123xyz789; user=testuser
```

**验证逻辑**: 同时验证session和user两个Cookie。

---

### IP伪造类

#### 内网IP验证

```
GET /api/ip/internal-only
```

**必需请求头** (任选其一):
```
X-Forwarded-For: 192.168.1.100
X-Forwarded-For: 10.0.0.1
X-Forwarded-For: 172.16.0.1
```

**验证逻辑**: 检查X-Forwarded-For是否为内网IP地址。

**内网IP范围**:
- 10.0.0.0/8
- 172.16.0.0/12
- 192.168.0.0/16
- 127.0.0.0/8

---

#### IP白名单验证

```
GET /api/ip/whitelist
```

**必需请求头**:
```
X-Real-IP: 10.10.10.10
```

**验证逻辑**: 检查X-Real-IP是否在白名单列表中。

**白名单IP**:
- 10.10.10.10
- 192.168.1.100
- 172.16.0.50

---

### User-Agent类

#### 移动端UA验证

```
GET /api/ua/mobile-only
```

**必需请求头** (示例):
```
User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)
```

或

```
User-Agent: Mozilla/5.0 (Linux; Android 10; SM-G960F)
```

**验证逻辑**: 检查User-Agent是否包含 "iPhone"、"Android"、"Mobile" 等移动端标识。

---

#### Bot UA验证

```
GET /api/ua/bot-only
```

**必需请求头** (示例):
```
User-Agent: Googlebot/2.1 (+http://www.google.com/bot.html)
```

**验证逻辑**: 检查User-Agent是否包含 "bot"、"spider"、"crawler" 等爬虫标识。

---

### 自定义头类

#### 自定义Header验证

```
GET /api/headers/custom
```

**必需请求头**:
```
X-Custom-Header: custom-value-123
```

---

#### Referer验证

```
GET /api/headers/referer
```

**必需请求头**:
```
Referer: https://trusted-site.com/
```

**验证逻辑**: 检查Referer是否来自trusted-site.com域名。

---

#### Origin验证

```
GET /api/headers/origin
```

**必需请求头**:
```
Origin: https://allowed-origin.com
```

**验证逻辑**: 检查Origin是否在允许列表中。

---

### 综合验证类

#### 完整认证验证

```
GET /api/auth/full
```

**必需请求头**:
```
Authorization: Bearer valid-token
X-Request-ID: any-unique-id
```

**验证逻辑**: 同时验证Bearer Token和Request ID。

---

#### 管理员面板验证

```
GET /api/admin/panel
```

**必需请求头**:
```
Authorization: Basic YWRtaW46cGFzc3dvcmQxMjM=
X-Admin-Token: super-secret-admin-token
X-Forwarded-For: 192.168.1.1
```

**验证逻辑**: 
1. 验证Basic Auth (admin:password123)
2. 验证管理员Token
3. 验证请求来自内网IP

这是最严格的验证端点，模拟真实的管理后台访问控制。

---

## 测试流程

### 使用changeHeaders插件测试

1. **配置Burp Suite代理**
   - 浏览器设置代理为 127.0.0.1:8080

2. **直接访问测试端点**
   - 访问任意API端点
   - 查看返回的错误信息
   - 错误信息中包含需要的请求头提示

3. **在changeHeaders中配置规则**
   - 打开changeHeaders标签页
   - 添加对应的请求头规则
   - 启用Proxy模块

4. **再次访问测试端点**
   - 请求头会自动添加
   - 验证成功

### 响应格式

#### 成功响应

```json
{
    "success": true,
    "message": "验证成功的描述",
    "request": {
        "method": "GET",
        "path": "/api/xxx",
        "headers": {
            "Authorization": "Bearer xxx",
            ...
        }
    }
}
```

#### 失败响应

```json
{
    "success": false,
    "message": "验证失败的描述",
    "hint": "需要添加的请求头提示",
    "request": {
        "method": "GET",
        "path": "/api/xxx",
        "headers": {...}
    }
}
```

---

## 日志配置

测试服务支持双输出日志：

- **控制台**: 实时显示请求日志
- **文件**: 保存到 `logs/server.log`

### 日志格式

```
2026-01-07 00:00:00 - INFO - 127.0.0.1 - GET /api/auth/bearer - 403
```

### 修改日志配置

编辑 `config.py` 文件：

```python
LOG_LEVEL = 'DEBUG'  # DEBUG, INFO, WARNING, ERROR
LOG_FILE = 'logs/server.log'
LOG_MAX_SIZE = 10 * 1024 * 1024  # 10MB
LOG_BACKUP_COUNT = 5
```

---

## 扩展开发

### 添加新的验证端点

1. 在 `handlers/` 目录下创建或编辑处理器文件

2. 继承 `BaseHandler` 类：

```python
from .base import BaseHandler

class MyHandler(BaseHandler):
    def handle_my_api(self):
        # 获取请求头
        my_header = self.get_header('X-My-Header')
        
        if not my_header:
            return self.fail('缺少X-My-Header', 
                           hint='X-My-Header: your-value')
        
        return self.ok('验证成功')
```

3. 在 `handlers/__init__.py` 中注册路由：

```python
API_ROUTES = {
    'GET': {
        ...
        '/api/my/endpoint': ('my_handler', 'handle_my_api'),
    }
}
```

---

## 相关文档

- [README](../README.md)
- [详细使用教程](usage-guide.md)
- [视频宣传脚本](video-script.md)
