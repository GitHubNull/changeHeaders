#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IP伪造头处理器"""

from .base import BaseHandler


class IPHandler(BaseHandler):
    """IP相关API"""
    
    def _is_internal_ip(self, ip: str) -> bool:
        """检查是否为内网IP"""
        return (
            ip.startswith('192.168.') or
            ip.startswith('10.') or
            ip.startswith('172.16.') or ip.startswith('172.17.') or
            ip.startswith('172.18.') or ip.startswith('172.19.') or
            ip.startswith('172.2') or ip.startswith('172.30.') or ip.startswith('172.31.') or
            ip in ('127.0.0.1', 'localhost')
        )
    
    def handle_internal(self):
        """内网IP验证 - X-Forwarded-For需为内网IP"""
        xff = self.get_header('X-Forwarded-For')
        
        if not xff:
            return self.fail('❌ 缺少 X-Forwarded-For 头', {
                'required': 'X-Forwarded-For: 192.168.x.x',
                'accepted': ['127.0.0.1', '192.168.*.*', '10.*.*.*']
            })
        
        ip = xff.split(',')[0].strip()
        
        if self._is_internal_ip(ip):
            return self.ok('✅ 内网IP验证通过！', {'ip': ip, 'type': 'Internal'})
        
        return self.fail('❌ 不是内网IP', {'ip': ip, 'hint': '需要192.168.x.x'})
    
    def handle_whitelist(self):
        """IP白名单验证 - X-Real-IP需为8.8.8.8"""
        real_ip = self.get_header('X-Real-IP')
        allowed = '8.8.8.8'
        
        if not real_ip:
            return self.fail('❌ 缺少 X-Real-IP 头', {
                'required': f'X-Real-IP: {allowed}'
            })
        
        if real_ip == allowed:
            return self.ok('✅ IP白名单验证通过！', {'ip': real_ip})
        
        return self.fail('❌ IP不在白名单', {'received': real_ip, 'allowed': allowed})
