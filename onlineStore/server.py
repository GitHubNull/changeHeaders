#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
changeHeaders Plugin Test Server
主入口文件 - 启动HTTP服务器
"""

import os
import socketserver
from http.server import SimpleHTTPRequestHandler
import json
import urllib.parse
import mimetypes

from config import SERVER_HOST, SERVER_PORT, BASE_DIR, STATIC_DIR, LOG_DIR
from config import CORS_ALLOW_ORIGIN, CORS_ALLOW_METHODS, CORS_ALLOW_HEADERS
from logger import app_logger as logger, http_logger
from handlers import route_request, API_ROUTES


class TestHTTPRequestHandler(SimpleHTTPRequestHandler):
    """自定义HTTP请求处理器"""
    
    def __init__(self, *args, **kwargs):
        # 设置静态文件根目录
        super().__init__(*args, directory=BASE_DIR, **kwargs)
    
    def send_cors_headers(self):
        """发送CORS头"""
        self.send_header('Access-Control-Allow-Origin', CORS_ALLOW_ORIGIN)
        self.send_header('Access-Control-Allow-Methods', CORS_ALLOW_METHODS)
        self.send_header('Access-Control-Allow-Headers', CORS_ALLOW_HEADERS)
    
    def send_json_response(self, data, status=200):
        """发送JSON响应"""
        response = json.dumps(data, ensure_ascii=False, indent=2)
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_cors_headers()
        self.end_headers()
        self.wfile.write(response.encode('utf-8'))
        
        # 记录响应日志
        http_logger.debug(f"Response [{status}]: {json.dumps(data, ensure_ascii=False)[:200]}...")
    
    def do_OPTIONS(self):
        """处理OPTIONS预检请求"""
        self.send_response(200)
        self.send_cors_headers()
        self.end_headers()
    
    def do_GET(self):
        """处理GET请求"""
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path
        
        http_logger.info(f"GET {self.path} from {self.client_address[0]}")
        self._log_headers()
        
        # API请求
        if path.startswith('/api/'):
            data, status = route_request(self, 'GET', path)
            self.send_json_response(data, status)
            return
        
        # 静态文件请求
        self._serve_static_file(path)
    
    def do_POST(self):
        """处理POST请求"""
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path
        
        http_logger.info(f"POST {self.path} from {self.client_address[0]}")
        self._log_headers()
        
        # API请求
        if path.startswith('/api/'):
            data, status = route_request(self, 'POST', path)
            self.send_json_response(data, status)
            return
        
        # 非API的POST请求返回405
        self.send_json_response({'error': 'Method not allowed'}, 405)
    
    def do_PUT(self):
        """处理PUT请求"""
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path
        
        http_logger.info(f"PUT {self.path} from {self.client_address[0]}")
        
        if path.startswith('/api/'):
            data, status = route_request(self, 'PUT', path)
            self.send_json_response(data, status)
            return
        
        self.send_json_response({'error': 'Method not allowed'}, 405)
    
    def do_DELETE(self):
        """处理DELETE请求"""
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path
        
        http_logger.info(f"DELETE {self.path} from {self.client_address[0]}")
        
        if path.startswith('/api/'):
            data, status = route_request(self, 'DELETE', path)
            self.send_json_response(data, status)
            return
        
        self.send_json_response({'error': 'Method not allowed'}, 405)
    
    def _serve_static_file(self, path):
        """处理静态文件请求"""
        # 默认页面
        if path == '/' or path == '':
            path = '/index.html'
        
        # 构建文件路径
        file_path = os.path.join(BASE_DIR, path.lstrip('/'))
        
        # 检查文件是否存在
        if os.path.isfile(file_path):
            # 获取MIME类型
            mime_type, _ = mimetypes.guess_type(file_path)
            if mime_type is None:
                mime_type = 'application/octet-stream'
            
            # 发送响应
            self.send_response(200)
            self.send_header('Content-Type', mime_type)
            self.send_cors_headers()
            self.end_headers()
            
            # 读取并发送文件内容
            with open(file_path, 'rb') as f:
                self.wfile.write(f.read())
        else:
            # 404
            self.send_json_response({'error': f'File not found: {path}'}, 404)
    
    def _log_headers(self):
        """记录请求头到日志"""
        for key, value in self.headers.items():
            http_logger.debug(f"  Header: {key}: {value}")
    
    def log_message(self, format, *args):
        """重写日志方法"""
        http_logger.info(f"HTTP: {args[0]}")
    
    def log_error(self, format, *args):
        """重写错误日志方法"""
        http_logger.error(f"HTTP Error: {format % args}")


def print_banner():
    """打印启动Banner"""
    logger.info("=" * 60)
    logger.info("  changeHeaders Plugin Test Server")
    logger.info("=" * 60)
    logger.info(f"  服务地址: http://{SERVER_HOST}:{SERVER_PORT}")
    logger.info(f"  前端页面: http://{SERVER_HOST}:{SERVER_PORT}/index.html")
    logger.info(f"  日志目录: {LOG_DIR}")
    logger.info("-" * 60)
    logger.info("  API端点:")
    
    for method, routes in API_ROUTES.items():
        for path in routes.keys():
            logger.info(f"    {method:6} {path}")
    
    logger.info("-" * 60)
    logger.info("  按 Ctrl+C 停止服务器")
    logger.info("=" * 60)


def main():
    """启动服务器"""
    print_banner()
    
    # 允许端口复用
    socketserver.TCPServer.allow_reuse_address = True
    
    with socketserver.TCPServer((SERVER_HOST, SERVER_PORT), TestHTTPRequestHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            logger.info("\n服务器已停止")


if __name__ == "__main__":
    main()
