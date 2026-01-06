#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""User-Agent处理器"""

from .base import BaseHandler


class UAHandler(BaseHandler):
    """User-Agent相关API"""
    
    def handle_mobile(self):
        """移动端UA验证 - 需含iPhone/Android/Mobile"""
        ua = self.get_header('User-Agent')
        
        if not ua:
            return self.fail('❌ 缺少 User-Agent 头', {
                'example': 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0...)'
            })
        
        ua_lower = ua.lower()
        keywords = ['iphone', 'android', 'mobile', 'ipad']
        
        for kw in keywords:
            if kw in ua_lower:
                device = kw.capitalize()
                return self.ok(f'✅ 移动端验证通过！检测到{device}', {
                    'device': device, 'ua': ua[:80]
                })
        
        return self.fail('❌ 需要移动端UA', {
            'received': ua[:80], 'hint': '需含iPhone/Android/Mobile'
        })
    
    def handle_bot(self):
        """爬虫UA验证 - 需含bot/spider/crawler"""
        ua = self.get_header('User-Agent')
        keywords = ['bot', 'spider', 'crawler', 'googlebot', 'bingbot', 'curl', 'wget', 'python']
        
        ua_lower = (ua or '').lower()
        for kw in keywords:
            if kw in ua_lower:
                return self.ok(f'✅ 爬虫验证通过！检测到{kw}', {'bot': kw})
        
        return self.fail('❌ 需要爬虫UA', {
            'received': (ua or '')[:80],
            'accepted': keywords,
            'example': 'Googlebot/2.1'
        })
