#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
配置模块 - 集中管理所有配置项
"""

import os

# ==================== 路径配置 ====================

# 项目根目录
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# 静态文件目录
STATIC_DIR = os.path.join(BASE_DIR, 'static')

# 日志目录
LOG_DIR = os.path.join(BASE_DIR, 'logs')

# ==================== 服务器配置 ====================

# 服务器地址
SERVER_HOST = "127.0.0.1"

# 服务器端口
SERVER_PORT = 8888

# ==================== 日志配置 ====================

# 日志文件路径
LOG_FILE = os.path.join(LOG_DIR, 'server.log')

# 日志级别: DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_LEVEL = "DEBUG"

# 日志格式
LOG_FORMAT = '%(asctime)s [%(levelname)s] %(name)s - %(message)s'

# 日志日期格式
LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

# 单个日志文件最大大小 (bytes)
LOG_MAX_BYTES = 10 * 1024 * 1024  # 10MB

# 保留的日志文件数量
LOG_BACKUP_COUNT = 5

# ==================== API配置 ====================

# API路由前缀
API_PREFIX = '/api'

# 允许的HTTP方法
ALLOWED_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']

# CORS配置
CORS_ALLOW_ORIGIN = '*'
CORS_ALLOW_METHODS = 'GET, POST, PUT, DELETE, OPTIONS'
CORS_ALLOW_HEADERS = '*'
