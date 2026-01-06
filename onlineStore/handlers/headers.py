#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""自定义头处理器"""

from .base import BaseHandler


class HeadersHandler(BaseHandler):
    """自定义头相关API"""
    
    def handle_custom(self):
        """多自定义头验证 - 需要X-Custom-Auth, X-Request-ID, X-Timestamp"""
        required = ['X-Custom-Auth', 'X-Request-ID', 'X-Timestamp']
        missing, received = [], {}
        
        for h in required:
            val = self.get_header(h)
            if val:
                received[h] = val
            else:
                missing.append(h)
        
        if missing:
            return self.fail('❌ 缺少自定义头', {
                'missing': missing,
                'required': {
                    'X-Custom-Auth': '任意值',
                    'X-Request-ID': 'req-12345',
                    'X-Timestamp': '1704067200'
                }
            }, 400)
        
        return self.ok('✅ 所有自定义头验证通过！', {'headers': received})
    
    def handle_referer(self):
        """Referer验证 - 需含trusted-site.com"""
        referer = self.get_header('Referer')
        
        if not referer:
            return self.fail('❌ 缺少 Referer 头', {
                'required': 'Referer: https://trusted-site.com/page'
            })
        
        if 'trusted-site.com' in referer:
            return self.ok('✅ Referer验证通过！', {'referer': referer})
        
        return self.fail('❌ Referer不受信任', {
            'received': referer, 'trusted': 'trusted-site.com'
        })
    
    def handle_origin(self):
        """Origin验证 - 需为https://allowed-origin.com"""
        origin = self.get_header('Origin')
        allowed = 'https://allowed-origin.com'
        
        if not origin:
            return self.fail('❌ 缺少 Origin 头', {'required': f'Origin: {allowed}'})
        
        if origin == allowed:
            return self.ok('✅ Origin验证通过！', {'origin': origin})
        
        return self.fail('❌ Origin不允许', {'received': origin, 'allowed': allowed})
