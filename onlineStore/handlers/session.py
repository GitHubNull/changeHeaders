#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Session/Cookie处理器"""

from .base import BaseHandler


class SessionHandler(BaseHandler):
    """Session/Cookie相关API"""
    
    def _parse_cookies(self) -> dict:
        """解析Cookie"""
        cookie = self.get_header('Cookie')
        cookies = {}
        if cookie:
            for item in cookie.split(';'):
                if '=' in item:
                    k, v = item.strip().split('=', 1)
                    cookies[k] = v
        return cookies
    
    def handle_session(self):
        """Session验证 - 需要: session=abc123xyz789"""
        cookie = self.get_header('Cookie')
        expected = 'abc123xyz789'
        
        if not cookie:
            return self.fail('❌ 缺少 Cookie 头', {
                'required': f'Cookie: session={expected}'
            }, 401)
        
        cookies = self._parse_cookies()
        session = cookies.get('session', '')
        
        if not session:
            return self.fail('❌ Cookie中缺少session', {
                'received': cookies, 'required': f'session={expected}'
            }, 401)
        
        if session == expected:
            return self.ok('✅ Session验证通过！', {'session': session})
        
        return self.fail('❌ Session无效', {'received': session, 'hint': expected}, 401)
    
    def handle_multi_cookie(self):
        """多Cookie验证 - 需要: token, user_id, role"""
        cookie = self.get_header('Cookie')
        required = {'token': 'secret123', 'user_id': '1001', 'role': 'admin'}
        
        if not cookie:
            return self.fail('❌ 缺少 Cookie 头', {
                'required': 'Cookie: token=secret123; user_id=1001; role=admin'
            }, 401)
        
        cookies = self._parse_cookies()
        missing, invalid = [], []
        
        for k, v in required.items():
            if k not in cookies:
                missing.append(k)
            elif cookies[k] != v:
                invalid.append(f"{k}(期望:{v})")
        
        if missing or invalid:
            return self.fail('❌ Cookie验证失败', {
                'missing': missing, 'invalid': invalid, 'required': required
            }, 401)
        
        return self.ok('✅ 所有Cookie验证通过！', {'cookies': required})
