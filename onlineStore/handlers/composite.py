#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""综合测试处理器"""

import base64
from .base import BaseHandler


class CompositeHandler(BaseHandler):
    """综合验证API"""
    
    def handle_full_auth(self):
        """综合认证 - Bearer + Session + API Key"""
        errors = []
        
        # Bearer Token
        auth = self.get_header('Authorization')
        if not auth or not auth.startswith('Bearer ') or len(auth) < 15:
            errors.append('Authorization: Bearer <token>')
        
        # Session Cookie
        cookie = self.get_header('Cookie')
        if 'session=abc123xyz789' not in (cookie or ''):
            errors.append('Cookie: session=abc123xyz789')
        
        # API Key
        if self.get_header('X-API-Key') != 'test-api-key-12345':
            errors.append('X-API-Key: test-api-key-12345')
        
        if errors:
            return self.fail('❌ 综合认证失败', {'missing': errors}, 401)
        
        return self.ok('🎉 综合认证全部通过！', {
            'passed': ['Bearer', 'Session', 'API-Key']
        })
    
    def handle_admin(self):
        """管理员面板 - Basic + Admin Token + 内网IP"""
        errors = []
        
        # Basic Auth
        auth = self.get_header('Authorization')
        basic_ok = False
        if auth and auth.startswith('Basic '):
            try:
                decoded = base64.b64decode(auth[6:]).decode('utf-8')
                basic_ok = (decoded == 'admin:password123')
            except:
                pass
        if not basic_ok:
            errors.append('Authorization: Basic YWRtaW46cGFzc3dvcmQxMjM=')
        
        # Admin Token
        if self.get_header('X-Admin-Token') != 'super-secret-admin':
            errors.append('X-Admin-Token: super-secret-admin')
        
        # 内网IP
        xff = self.get_header('X-Forwarded-For')
        ip = xff.split(',')[0].strip() if xff else ''
        is_internal = ip.startswith('192.168.') or ip.startswith('10.') or ip == '127.0.0.1'
        if not is_internal:
            errors.append('X-Forwarded-For: 192.168.x.x')
        
        if errors:
            return self.fail('🚫 管理员面板拒绝访问', {'missing': errors, 'level': 'HIGH'})
        
        return self.ok('🔓 管理员面板访问成功！', {
            'user': 'admin', 'level': 'FULL', 'ip': ip
        })
