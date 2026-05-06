#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
日志模块 - 统一日志管理
"""

import os
import sys
import logging
import logging.handlers

from config import (
    LOG_DIR, LOG_FILE, LOG_LEVEL, LOG_FORMAT, 
    LOG_DATE_FORMAT, LOG_MAX_BYTES, LOG_BACKUP_COUNT
)


def setup_logger(name: str = None) -> logging.Logger:
    """
    配置并返回日志记录器
    
    Args:
        name: 日志记录器名称，默认为None（使用root logger）
    
    Returns:
        配置好的日志记录器
    """
    # 创建日志目录
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)
    
    # 获取日志记录器
    logger = logging.getLogger(name)
    
    # 如果已经配置过，直接返回
    if logger.handlers:
        return logger
    
    # 设置日志级别
    level = getattr(logging, LOG_LEVEL.upper(), logging.DEBUG)
    logger.setLevel(level)
    
    # 创建格式化器
    formatter = logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
    
    # 控制台处理器
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # 文件处理器（轮转日志）
    file_handler = logging.handlers.RotatingFileHandler(
        LOG_FILE,
        maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUP_COUNT,
        encoding='utf-8'
    )
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    return logger


# 创建默认的应用日志记录器
app_logger = setup_logger('app')

# 创建HTTP请求日志记录器
http_logger = setup_logger('http')

# 创建API日志记录器
api_logger = setup_logger('api')


def get_logger(name: str = 'app') -> logging.Logger:
    """
    获取指定名称的日志记录器
    
    Args:
        name: 日志记录器名称
    
    Returns:
        日志记录器
    """
    return setup_logger(name)
