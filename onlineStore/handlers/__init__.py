#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
handlers模块包
按功能类型组织API处理器
"""

from .base import BaseHandler
from .auth import AuthHandler
from .session import SessionHandler  
from .ip import IPHandler
from .ua import UAHandler
from .headers import HeadersHandler
from .composite import CompositeHandler

# API路由表
API_ROUTES = {
    'GET': {
        '/api/echo': ('base', 'handle_echo'),
        # 认证类
        '/api/auth/bearer': ('auth', 'handle_bearer'),
        '/api/auth/basic': ('auth', 'handle_basic'),
        '/api/auth/api-key': ('auth', 'handle_api_key'),
        # Cookie/Session类
        '/api/session/required': ('session', 'handle_session'),
        '/api/session/multi-cookie': ('session', 'handle_multi_cookie'),
        # IP类
        '/api/ip/internal-only': ('ip', 'handle_internal'),
        '/api/ip/whitelist': ('ip', 'handle_whitelist'),
        # UA类
        '/api/ua/mobile-only': ('ua', 'handle_mobile'),
        '/api/ua/bot-only': ('ua', 'handle_bot'),
        # 自定义头类
        '/api/headers/custom': ('headers', 'handle_custom'),
        '/api/headers/referer': ('headers', 'handle_referer'),
        '/api/headers/origin': ('headers', 'handle_origin'),
        # 综合测试
        '/api/auth/full': ('composite', 'handle_full_auth'),
        '/api/admin/panel': ('composite', 'handle_admin'),
    },
    'POST': {
        '/api/echo': ('base', 'handle_echo'),
        '/api/auth/bearer': ('auth', 'handle_bearer'),
        '/api/auth/basic': ('auth', 'handle_basic'),
        '/api/auth/api-key': ('auth', 'handle_api_key'),
        '/api/auth/full': ('composite', 'handle_full_auth'),
    },
    'PUT': {'/api/echo': ('base', 'handle_echo')},
    'DELETE': {'/api/echo': ('base', 'handle_echo')},
}

# Handler映射
HANDLERS = {
    'base': BaseHandler,
    'auth': AuthHandler,
    'session': SessionHandler,
    'ip': IPHandler,
    'ua': UAHandler,
    'headers': HeadersHandler,
    'composite': CompositeHandler,
}


def route_request(http_handler, method: str, path: str):
    """路由请求"""
    routes = API_ROUTES.get(method, {})
    route_info = routes.get(path)
    
    if route_info:
        handler_name, method_name = route_info
        handler_cls = HANDLERS.get(handler_name)
        if handler_cls:
            handler = handler_cls(http_handler)
            method_func = getattr(handler, method_name, None)
            if method_func:
                return method_func()
    
    return {'success': False, 'message': f'API不存在: {path}'}, 404
