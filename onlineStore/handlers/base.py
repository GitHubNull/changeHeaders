#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""基础处理器 - 提供公共方法"""

import urllib.parse
from datetime import datetime
from typing import Dict, Any, Tuple


class BaseHandler:
    """API基础处理器"""
    
    def __init__(self, http_handler):
        self.h = http_handler
        self.headers = http_handler.headers
    
    def get_header(self, name: str, default: str = '') -> str:
        """获取请求头"""
        return self.headers.get(name, default)
    
    def get_request_info(self) -> Dict[str, Any]:
        """获取请求信息"""
        headers = {k: v for k, v in self.headers.items()}
        content_length = int(self.headers.get('Content-Length', 0))
        body = ''
        if content_length > 0:
            body = self.h.rfile.read(content_length).decode('utf-8')
        
        parsed = urllib.parse.urlparse(self.h.path)
        return {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'method': self.h.command,
            'path': parsed.path,
            'query': urllib.parse.parse_qs(parsed.query),
            'headers': headers,
            'body': body,
            'client': f"{self.h.client_address[0]}:{self.h.client_address[1]}"
        }
    
    def ok(self, msg: str, data: dict = None) -> Tuple[Dict, int]:
        """成功响应"""
        resp = {'success': True, 'message': msg, 'request': self.get_request_info()}
        if data:
            resp['data'] = data
        return resp, 200
    
    def fail(self, msg: str, data: dict = None, status: int = 403) -> Tuple[Dict, int]:
        """失败响应"""
        resp = {'success': False, 'message': msg, 'request': self.get_request_info()}
        if data:
            resp['data'] = data
        return resp, status
    
    def handle_echo(self) -> Tuple[Dict, int]:
        """Echo - 回显请求信息"""
        return self.ok('请求回显 - 查看所有请求头')
