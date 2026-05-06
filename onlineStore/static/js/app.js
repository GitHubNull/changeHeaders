/**
 * changeHeaders 插件测试平台 - 前端逻辑
 */

// ==================== 状态管理 ====================
const state = {
    lastResponse: null,
    currentTab: 'json'
};

// ==================== DOM元素 ====================
const elements = {
    jsonView: () => document.getElementById('json-view'),
    headersView: () => document.getElementById('headers-view'),
    headersTbody: () => document.getElementById('headers-tbody'),
    statusDot: () => document.getElementById('status-dot'),
    statusText: () => document.getElementById('status-text'),
    requestInfo: () => document.getElementById('request-info'),
    toast: () => document.getElementById('toast')
};

// ==================== API请求 ====================

/**
 * 发送HTTP请求
 * @param {string} method - HTTP方法
 * @param {string} path - 请求路径
 * @param {object} body - 请求体（可选）
 */
async function sendRequest(method, path, body = null) {
    const statusDot = elements.statusDot();
    const statusText = elements.statusText();
    const requestInfo = elements.requestInfo();
    
    // 更新状态为加载中
    statusDot.classList.add('loading');
    statusText.textContent = '请求中...';
    
    const startTime = Date.now();
    
    try {
        const options = {
            method: method,
            headers: {
                'Content-Type': 'application/json'
            }
        };
        
        if (body && (method === 'POST' || method === 'PUT')) {
            options.body = JSON.stringify(body);
        }
        
        const response = await fetch(path, options);
        const data = await response.json();
        
        const elapsed = Date.now() - startTime;
        
        // 保存响应
        state.lastResponse = data;
        
        // 显示响应
        displayResponse(data);
        
        // 更新状态
        statusDot.classList.remove('loading');
        statusText.textContent = `${response.status} OK`;
        requestInfo.textContent = `${method} ${path} - ${elapsed}ms`;
        
    } catch (error) {
        // 错误处理
        statusDot.classList.remove('loading');
        statusText.textContent = '请求失败';
        requestInfo.textContent = error.message;
        
        elements.jsonView().innerHTML = 
            `<div style="color: #f56565;">请求失败: ${error.message}</div>`;
    }
}

// ==================== 响应显示 ====================

/**
 * 显示响应数据
 * @param {object} data - 响应数据
 */
function displayResponse(data) {
    // JSON视图
    const jsonView = elements.jsonView();
    jsonView.textContent = JSON.stringify(data, null, 2);
    
    // 请求头表格
    if (data.request && data.request.headers) {
        const tbody = elements.headersTbody();
        tbody.innerHTML = '';
        
        // 重要的请求头列表
        const importantHeaders = [
            'authorization', 'cookie', 'x-token', 'x-forwarded-for', 
            'x-real-ip', 'x-client-ip', 'user-agent', 'referer', 'origin'
        ];
        
        for (const [key, value] of Object.entries(data.request.headers)) {
            const tr = document.createElement('tr');
            const isImportant = importantHeaders.includes(key.toLowerCase());
            
            tr.innerHTML = `
                <td class="header-key">${isImportant ? '<span class="highlight">' + key + '</span>' : key}</td>
                <td class="header-value">${escapeHtml(value)}</td>
            `;
            tbody.appendChild(tr);
        }
    }
}

/**
 * HTML转义
 * @param {string} text - 原始文本
 * @returns {string} 转义后的文本
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ==================== 标签切换 ====================

/**
 * 切换显示标签
 * @param {string} tab - 标签名称 (json/headers)
 */
function switchTab(tab) {
    state.currentTab = tab;
    
    // 更新标签按钮状态
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.response-json, .response-headers').forEach(el => el.classList.remove('active'));
    
    if (tab === 'json') {
        document.querySelector('.tab-btn:first-child').classList.add('active');
        elements.jsonView().classList.add('active');
    } else {
        document.querySelector('.tab-btn:last-child').classList.add('active');
        elements.headersView().classList.add('active');
    }
}

// ==================== 剪贴板操作 ====================

/**
 * 复制文本到剪贴板
 * @param {string} text - 要复制的文本
 */
function copyToClipboard(text) {
    // 尝试使用现代API
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(() => {
            showToast('✓ 已复制到剪贴板');
        }).catch(err => {
            fallbackCopy(text);
        });
    } else {
        fallbackCopy(text);
    }
}

/**
 * 降级复制方法
 * @param {string} text - 要复制的文本
 */
function fallbackCopy(text) {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    
    try {
        document.execCommand('copy');
        showToast('✓ 已复制到剪贴板');
    } catch (err) {
        showToast('✗ 复制失败');
    }
    
    document.body.removeChild(textarea);
}

// ==================== 提示消息 ====================

/**
 * 显示Toast提示
 * @param {string} message - 提示消息
 * @param {number} duration - 显示时长(ms)
 */
function showToast(message, duration = 2000) {
    const toast = elements.toast();
    toast.textContent = message;
    toast.classList.add('show');
    
    setTimeout(() => {
        toast.classList.remove('show');
    }, duration);
}

// ==================== 请求头样本数据 ====================

const headerSamples = {
    auth: `Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoidGVzdCJ9.test
Cookie: session=abc123; token=xyz789
X-Token: my-secret-token-12345`,
    
    ip: `X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Client-IP: 127.0.0.1`,
    
    mobile: `User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15`,
    
    custom: `X-Custom-Header: custom-value-123
X-Request-ID: req-${Date.now()}
X-Debug-Mode: true`,
    
    referer: `Referer: https://www.google.com/
Origin: https://trusted-site.com
X-Requested-With: XMLHttpRequest`,
    
    content: `Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Accept: application/json
Content-Type: application/json`
};

/**
 * 复制预定义的请求头样本
 * @param {string} type - 样本类型
 */
function copySample(type) {
    const sample = headerSamples[type];
    if (sample) {
        // 动态生成的样本
        let text = sample;
        if (type === 'custom') {
            text = `X-Custom-Header: custom-value-123
X-Request-ID: req-${Date.now()}
X-Debug-Mode: true`;
        }
        copyToClipboard(text);
    }
}

// ==================== 初始化 ====================

document.addEventListener('DOMContentLoaded', () => {
    console.log('changeHeaders Test Platform initialized');
});
