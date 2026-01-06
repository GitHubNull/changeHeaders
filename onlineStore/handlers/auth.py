#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""认证处理器 - Bearer/Basic/API Key"""

import base64
from .base import BaseHandler


class AuthHandler(BaseHandler):
    """认证相关API"""
    
    def handle_bearer(self):
        """Bearer Token验证"""
        auth = self.get_header('Authorization')
        
        if not auth:
            return self.fail('❌ 缺少 Authorization 头', {
                'required': 'Authorization: Bearer <token>',
                'example': 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.test'
            }, 401)
        
        if not auth.startswith('Bearer '):
            return self.fail('❌ 需要 Bearer 类型', {'received': auth}, 401)
        
        token = auth[7:]
        if len(token) < 10:
            return self.fail('❌ Token太短(至少10字符)', {'length': len(token)}, 401)
        
        return self.ok('✅ Bearer Token验证通过！', {
            'token': token[:20] + '...' if len(token) > 20 else token
        })
    
    def handle_basic(self):
        """Basic认证 - 账号: admin:password123"""
        auth = self.get_header('Authorization')
        
        if not auth:
            return self.fail('❌ 缺少 Authorization 头', {
                'required': 'Authorization: Basic YWRtaW46cGFzc3dvcmQxMjM=',
                'credentials': 'admin:password123'
            }, 401)
        
        if not auth.startswith('Basic '):
            return self.fail('❌ 需要 Basic 类型', {'received': auth}, 401)
        
        try:
            decoded = base64.b64decode(auth[6:]).decode('utf-8')
            user, pwd = decoded.split(':', 1)
            
            if user == 'admin' and pwd == 'password123':
                return self.ok('✅ Basic认证通过！', {'user': user})
            return self.fail('❌ 用户名或密码错误', {'hint': 'admin:password123'}, 401)
        except:
            return self.fail('❌ Base64解码失败', {}, 401)
    
    def handle_api_key(self):
        """API Key验证 - Key: test-api-key-12345"""
        key = self.get_header('X-API-Key')
        expected = 'test-api-key-12345'
        
        if not key:
            return self.fail('❌ 缺少 X-API-Key 头', {
                'required': f'X-API-Key: {expected}'
            }, 401)
        
        if key == expected:
            return self.ok('✅ API Key验证通过！')
        
        return self.fail('❌ API Key无效', {'hint': expected}, 401)
