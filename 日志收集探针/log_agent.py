#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
实时攻防平台日志收集Agent
被动收集靶标系统的各种日志并发送到平台
"""

import requests
import time
import json
import os
import hashlib
import psutil
import socket
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import threading

class LogAgentConfig:
    """Agent配置类"""
    def __init__(self, config_file='agent_config.json'):
        self.config_file = config_file
        self.config = {}  # 先初始化config为空字典
        self.load_config()  # 然后加载配置
    
    def load_config(self):
        """加载配置文件"""
        # 获取本机IP地址
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
        except:
            local_ip = "127.0.0.1"  # 如果获取失败使用默认IP
        
        default_config = {
            "platform_url": "http://localhost:5000/api/logs/collect",
            "target_id": f"target_{local_ip.replace('.', '_')}",  # 使用IP作为ID
            "target_name": f"Target-{local_ip}",  # 使用IP作为名称
            "target_ip": local_ip,  # 使用实际IP
            "log_sources": {
                "web_access": {
                    "enabled": True,
                    "log_file": "/var/log/apache2/access.log",
                    "severity": "medium"
                },
                "web_error": {
                    "enabled": True,
                    "log_file": "/var/log/apache2/error.log",
                    "severity": "high"
                },
                "ssh_log": {
                    "enabled": True,
                    "log_file": "/var/log/auth.log",
                    "severity": "high"
                },
                "system_log": {
                    "enabled": True,
                    "log_file": "/var/log/syslog",
                    "severity": "medium"
                }
            },
            "file_integrity": {
                "enabled": True,
                "monitor_paths": ["/var/www/html"],
                "file_extensions": [".php", ".html", ".js", ".css"],
                "severity": "critical"
            },
            "network_monitor": {
                "enabled": True,
                "monitor_ports": [80, 443, 22, 21, 23],
                "severity": "high"
            },
            "malware_detection": {
                "enabled": True,
                "scan_paths": ["/var/www/html"],
                "suspicious_extensions": [".php", ".asp", ".jsp"],
                "severity": "critical"
            },
            "send_interval": 3,
            "batch_size": 10
        }
        
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    user_config = json.load(f)
                # 合并配置
                default_config.update(user_config)
            except Exception as e:
                print(f"加载配置文件失败: {e}, 使用默认配置")
        
        self.config = default_config  # 这里正确设置config属性
        self.save_config()
    
    def save_config(self):
        """保存配置文件"""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"保存配置文件失败: {e}")
    
    def get(self, key, default=None):
        """获取配置项"""
        return self.config.get(key, default)

class FileIntegrityMonitor(FileSystemEventHandler):
    """文件完整性监控"""
    def __init__(self, agent):
        self.agent = agent
        self.file_hashes = {}
        
        # 初始化文件哈希记录
        for path in self.agent.config.get('file_integrity', {}).get('monitor_paths', []):
            self.scan_directory(path)
    
    def scan_directory(self, path):
        """扫描目录并记录文件哈希"""
        if not os.path.exists(path):
            return
        
        extensions = self.agent.config.get('file_integrity', {}).get('file_extensions', [])
        
        for root, dirs, files in os.walk(path):
            for file in files:
                if any(file.endswith(ext) for ext in extensions):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'rb') as f:
                            file_hash = hashlib.md5(f.read()).hexdigest()
                        self.file_hashes[file_path] = file_hash
                    except Exception as e:
                        print(f"计算文件哈希失败 {file_path}: {e}")
    
    def on_modified(self, event):
        """文件修改事件"""
        if event.is_directory:
            return
        
        file_path = event.src_path
        extensions = self.agent.config.get('file_integrity', {}).get('file_extensions', [])
        
        if any(file_path.endswith(ext) for ext in extensions):
            try:
                with open(file_path, 'rb') as f:
                    new_hash = hashlib.md5(f.read()).hexdigest()
                
                old_hash = self.file_hashes.get(file_path)
                if old_hash and old_hash != new_hash:
                    self.agent.log_event({
                        'type': 'file_integrity',
                        'severity': self.agent.config.get('file_integrity', {}).get('severity', 'critical'),
                        'message': f'文件被篡改: {file_path}',
                        'details': {
                            'file_path': file_path,
                            'old_hash': old_hash,
                            'new_hash': new_hash
                        }
                    })
                
                self.file_hashes[file_path] = new_hash
                
            except Exception as e:
                print(f"检查文件修改失败 {file_path}: {e}")
    
    def on_created(self, event):
        """文件创建事件"""
        if event.is_directory:
            return
        
        file_path = event.src_path
        extensions = self.agent.config.get('malware_detection', {}).get('suspicious_extensions', [])
        
        if any(file_path.endswith(ext) for ext in extensions):
            self.agent.log_event({
                'type': 'malware_detection',
                'severity': self.agent.config.get('malware_detection', {}).get('severity', 'critical'),
                'message': f'检测到可疑文件创建: {file_path}',
                'details': {
                    'file_path': file_path,
                    'file_name': os.path.basename(file_path)
                }
            })

class LogAgent:
    """日志收集Agent主类"""
    def __init__(self):
        self.config = LogAgentConfig()
        self.log_queue = []
        self.queue_lock = threading.Lock()
        
        # 添加去重相关属性
        self.recent_logs = set()  # 用于去重的集合
        self.duplicate_window = 2  # 2秒内的重复日志不上传
        
        # 添加频率分析相关的属性
        self.request_counter = {}  # 请求计数器
        self.suspicious_ips = set()  # 可疑IP列表
        
        # 初始化各监控模块
        self.setup_monitoring()
        
        # 启动后台线程
        self.start_background_tasks()


    def extract_ip_from_log(self, log_line):
        """从日志行中提取IP地址"""
        try:
            # 常见Web服务器日志格式：IP - - [timestamp] "method url protocol" status size
            # 例如：192.168.1.1 - - [01/Nov/2025:23:50:00 +0800] "GET /test HTTP/1.1" 404 123
            
            # 方法1：直接按空格分割，第一个字段通常是IP
            parts = log_line.split()
            if parts:
                # 检查第一个字段是否是IP地址格式
                first_part = parts[0]
                if self.is_valid_ip(first_part) and first_part != "127.0.0.1":  # 过滤127.0.0.1
                    return first_part
            
            # 方法2：查找IP地址模式
            import re
            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            ip_matches = re.findall(ip_pattern, log_line)
            if ip_matches:
                for ip in ip_matches:
                    if self.is_valid_ip(ip) and ip != "127.0.0.1":  # 过滤127.0.0.1
                        return ip
            
            # 方法3：Apache/Nginx标准格式 "IP - - "
            if ' - - ' in log_line:
                ip_part = log_line.split(' - - ')[0]
                if self.is_valid_ip(ip_part.strip()) and ip_part.strip() != "127.0.0.1":  # 过滤127.0.0.1
                    return ip_part.strip()
                    
            return "未知IP"
            
        except Exception as e:
            print(f"提取IP地址失败: {e}")
            return "未知IP"



    def is_valid_ip(self, ip_str):
        """验证IP地址格式"""
        try:
            parts = ip_str.split('.')
            if len(parts) != 4:
                return False
            for part in parts:
                if not part.isdigit():
                    return False
                num = int(part)
                if num < 0 or num > 255:
                    return False
            return True
        except:
            return False

    def setup_monitoring(self):
        """设置监控模块"""
        # 文件完整性监控
        if self.config.get('file_integrity', {}).get('enabled', False):
            self.file_monitor = FileIntegrityMonitor(self)
            self.observer = Observer()
            for path in self.config.get('file_integrity', {}).get('monitor_paths', []):
                if os.path.exists(path):
                    self.observer.schedule(self.file_monitor, path, recursive=True)
            self.observer.start()
        
        # 网络连接监控
        if self.config.get('network_monitor', {}).get('enabled', False):
            self.monitor_ports = self.config.get('network_monitor', {}).get('monitor_ports', [])
            self.network_connections = set()
    
    def start_background_tasks(self):
        """启动后台任务"""
        # 日志收集线程
        threading.Thread(target=self.log_collector, daemon=True).start()
        
        # 日志发送线程
        threading.Thread(target=self.log_sender, daemon=True).start()
        
        # 网络监控线程
        if self.config.get('network_monitor', {}).get('enabled', False):
            threading.Thread(target=self.network_monitor, daemon=True).start()
        
        # 系统信息监控线程
        threading.Thread(target=self.system_monitor, daemon=True).start()
    
    def log_event(self, event_data):
        """记录事件到队列"""
        event_data.update({
            'timestamp': datetime.now().isoformat(),
            'target_id': self.config.get('target_id'),
            'target_name': self.config.get('target_name'),
            'target_ip': self.config.get('target_ip')  # 确保使用配置中的IP
        })
        
        with self.queue_lock:
            self.log_queue.append(event_data)




    def log_collector(self):
        """日志收集器"""
        log_sources = self.config.get('log_sources', {})
        
        while True:
            try:
                for source_name, source_config in log_sources.items():
                    if source_config.get('enabled', False):
                        self.collect_log_file(source_name, source_config)
                
                time.sleep(1)  # 每秒检查一次
                
            except Exception as e:
                print(f"日志收集错误: {e}")
                time.sleep(5)
    
    def collect_log_file(self, source_name, source_config):
        """收集单个日志文件"""
        log_file = source_config.get('log_file')
        if not log_file or not os.path.exists(log_file):
            return
        
        # 添加文件位置跟踪
        if not hasattr(self, 'file_positions'):
            self.file_positions = {}
        
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                # 获取当前文件大小
                current_size = os.path.getsize(log_file)
                
                # 如果是第一次读取该文件，从末尾开始
                if log_file not in self.file_positions:
                    self.file_positions[log_file] = current_size
                    return
                
                # 如果文件被截断或重置，重置位置
                if current_size < self.file_positions[log_file]:
                    self.file_positions[log_file] = 0
                
                # 如果有新内容
                if current_size > self.file_positions[log_file]:
                    f.seek(self.file_positions[log_file])
                    new_lines = f.readlines()
                    
                    for line in new_lines:
                        line = line.strip()
                        if line:  # 只处理非空行
                            self.analyze_log_line(line, source_name, source_config)
                            # 添加频率分析
                            if source_name in ['web_access', 'web_error']:
                                self.analyze_request_frequency(line, source_name)
                    
                    # 更新文件位置
                    self.file_positions[log_file] = f.tell()
                    
        except Exception as e:
            print(f"读取日志文件失败 {log_file}: {e}")



    def analyze_log_line(self, line, source_name, source_config):
        """分析日志行"""
        if not line:
            return
        
        line_lower = line.lower()
        # 过滤系统管理操作相关的日志（不记录到平台）
        if any(keyword in line_lower for keyword in [
            '管理员清除了', 
            '管理员清除',
            '管理员创建了',
            '管理员删除了',
            '管理员重置了',
            'admin cleared',
            'admin created',
            'admin deleted',
            'admin reset'
        ]):
            return  # 直接返回，不记录这类系统管理日志
        
        # 检测SQL注入攻击
        if any(keyword in line_lower for keyword in ['union select', 'select *', 'information_schema', 
                                                    'sleep(', 'benchmark(', 'drop table', 'insert into',
                                                    'update set', 'delete from', 'or 1=1', "' or '1'='1"]):
            self.log_event({
                'type': 'attack',
                'severity': 'high',
                'message': '检测到SQL注入攻击',
                'source': source_name,
                'details': {
                    'raw_log': line[:100],  # 只保留前100个字符
                    'attack_type': 'sql_injection',
                    'technique': 'database_manipulation'
                }
            })
        
        # 检测LFI/RFI攻击
        elif any(keyword in line_lower for keyword in ['php://', 'phar://', 'zip://', 'data://', 
                                                    'expect://', 'input://', 'glob://']):
            self.log_event({
                'type': 'attack',
                'severity': 'critical',
                'message': '检测到PHP包装器攻击',
                'source': source_name,
                'details': {
                    'raw_log': line[:100],
                    'attack_type': 'file_inclusion',
                    'technique': 'php_wrapper_abuse'
                }
            })



        # 检测目录扫描工具
        elif any(pattern in line_lower for pattern in ['dirb', 'gobuster', 'dirbuster', 'wfuzz']):
            self.log_event({
                'type': 'attack', 
                'severity': 'high',
                'message': '检测到目录扫描工具',
                'source': source_name,
                'details': {
                    'raw_log': line[:100],
                    'attack_type': 'directory_scanning',
                    'technique': 'automated_tool_usage'
                }
            })

        # 检测安全扫描工具
        elif any(scanner in line_lower for scanner in ['sqlmap', 'nmap', 'nikto', 'metasploit', 'burpsuite']):
            self.log_event({
                'type': 'attack',
                'severity': 'high', 
                'message': '检测到安全扫描工具',
                'source': source_name,
                'details': {
                    'raw_log': line[:100],
                    'attack_type': 'vulnerability_scanning',
                    'technique': 'automated_scanning'
                }
            })

        # 检测网站爆破（404/403错误）
        elif any(keyword in line_lower for keyword in [' 404 ', ' 403 ', 'not found', 'forbidden']):
            # 从日志行中提取IP地址
            client_ip = self.extract_ip_from_log(line)
            
            # 只有当成功提取到IP且不是127.0.0.1时才记录
            if client_ip and client_ip != "未知IP" and client_ip != "127.0.0.1":
                self.log_event({
                    'type': 'attack',
                    'severity': 'medium',
                    'message': f'可疑IP {client_ip} 网站爆破(404/403)',
                    'source': source_name,
                    'details': {
                        'raw_log': line[:100],
                        'attack_type': 'web_scanning',
                        'technique': 'directory_bruteforce',
                        'source_ip': client_ip
                    }
                })


        # 检测敏感文件访问
        elif any(keyword in line_lower for keyword in ['/admin', '/login', '/wp-admin', '/.git/', '/.env', 
                                                    '/backup', '/config', '/database']):
            self.log_event({
                'type': 'attack',
                'severity': 'medium',
                'message': '访问敏感路径',
                'source': source_name,
                'details': {
                    'raw_log': line[:100],
                    'attack_type': 'web_scanning', 
                    'technique': 'sensitive_path_probing'
                }
            })
        
        # 检测SSRF攻击
        elif any(keyword in line_lower for keyword in ['url=', 'proxy=', 'curl', 'file_get_contents', 
                                                    'http://localhost', 'http://127.0.0.1']):
            self.log_event({
                'type': 'attack',
                'severity': 'high',
                'message': '检测到SSRF攻击尝试',
                'source': source_name,
                'details': {
                    'raw_log': line[:100],
                    'attack_type': 'ssrf',
                    'technique': 'server_side_request_forgery'
                }
            })

        # 检测XSS攻击
        elif any(keyword in line_lower for keyword in ['<script>', 'javascript:', 'onerror=', 'onload=',
                                                    'alert(', 'document.cookie', 'eval(', 'innerhtml']):
            self.log_event({
                'type': 'attack',
                'severity': 'high',
                'message': '检测到XSS攻击',
                'source': source_name,
                'details': {
                    'raw_log': line[:100],
                    'attack_type': 'xss',
                    'technique': 'client_side_execution'
                }
            })
        
        # 检测命令注入
        elif any(keyword in line_lower for keyword in ['; ls', '; cat', '; whoami', '; id', '| bash',
                                                    '`', '$(', 'system(', 'exec(', 'passthru(']):
            self.log_event({
                'type': 'attack',
                'severity': 'critical',
                'message': '检测到命令注入',
                'source': source_name,
                'details': {
                    'raw_log': line[:100],
                    'attack_type': 'command_injection',
                    'technique': 'os_command_execution'
                }
            })
        
        # 检测文件包含
        elif any(keyword in line_lower for keyword in ['../', '..\\', '/etc/passwd', 'c:\\windows',
                                                    'include(', 'require(', 'file_get_contents(']):
            self.log_event({
                'type': 'attack',
                'severity': 'high',
                'message': '检测到文件包含攻击',
                'source': source_name,
                'details': {
                    'raw_log': line[:100],
                    'attack_type': 'file_inclusion',
                    'technique': 'local_file_access'
                }
            })
        
        # 检测暴力破解
        elif 'failed password' in line_lower or 'authentication failure' in line_lower:
            self.log_event({
                'type': 'attack',
                'severity': 'medium',
                'message': '检测到暴力破解尝试',
                'source': source_name,
                'details': {
                    'raw_log': line[:100],
                    'attack_type': 'brute_force',
                    'technique': 'credential_guessing'
                }
            })
        
        # 检测端口扫描
        elif any(keyword in line_lower for keyword in ['connection reset', 'refused connect', 
                                                    'syn sent', 'port scan', 'nmap']):
            self.log_event({
                'type': 'attack',
                'severity': 'medium',
                'message': '检测到端口扫描',
                'source': source_name,
                'details': {
                    'raw_log': line[:100],
                    'attack_type': 'port_scanning',
                    'technique': 'reconnaissance'
                }
            })
        
        # 检测目录遍历
        elif any(keyword in line_lower for keyword in ['/../', '/./', '....//', '....\\\\']):
            self.log_event({
                'type': 'attack',
                'severity': 'high',
                'message': '检测到目录遍历攻击',
                'source': source_name,
                'details': {
                    'raw_log': line[:100],
                    'attack_type': 'directory_traversal',
                    'technique': 'path_manipulation'
                }
            })
        
        # 登录检测
        elif any(keyword in line_lower for keyword in ['login', 'auth', 'password']):
            if 'success' in line_lower or 'accepted' in line_lower:
                self.log_event({
                    'type': 'login',
                    'severity': 'low',
                    'message': '登录成功',
                    'source': source_name,
                    'details': {'raw_log': line[:100], 'status': 'success'}
                })
            elif 'failed' in line_lower or 'invalid' in line_lower:
                self.log_event({
                    'type': 'login',
                    'severity': 'medium',
                    'message': '登录失败',
                    'source': source_name,
                    'details': {'raw_log': line[:100], 'status': 'failed'}
                })   


    
    def analyze_request_frequency(self, line, source_name):
        """分析请求频率"""
        try:
            # 从日志行中提取IP地址（适用于Apache/Nginx访问日志）
            if ' - - ' in line and 'HTTP' in line:
                parts = line.split()
                if len(parts) > 3:
                    client_ip = parts[0]
                    
                    # 更新计数器
                    current_time = int(time.time())
                    time_window = current_time // 60  # 每分钟一个窗口
                    
                    key = f"{client_ip}_{time_window}"
                    self.request_counter[key] = self.request_counter.get(key, 0) + 1
                    
                    # 检测高频请求（每分钟超过100次）
                    if self.request_counter[key] > 100 and client_ip not in self.suspicious_ips:
                        self.suspicious_ips.add(client_ip)
                        self.log_event({
                            'type': 'attack',
                            'severity': 'high',
                            'message': f'检测到高频请求攻击，IP: {client_ip}，频率: {self.request_counter[key]}次/分钟',
                            'source': source_name,
                            'details': {
                                'source_ip': client_ip,
                                'request_count': self.request_counter[key],
                                'attack_type': 'web_bruteforce',
                                'technique': 'request_flood'
                            }
                        })
                    
                    # 清理过期计数器（保留最近10分钟）
                    expired_keys = [k for k in self.request_counter.keys() 
                                if int(k.split('_')[1]) < time_window - 10]
                    for k in expired_keys:
                        del self.request_counter[k]
                        
        except Exception as e:
            print(f"频率分析错误: {e}")




    def network_monitor(self):
        """网络连接监控"""
        while True:
            try:
                current_connections = set()
                for conn in psutil.net_connections():
                    if (conn.status == 'ESTABLISHED' and 
                        hasattr(conn, 'laddr') and conn.laddr and 
                        hasattr(conn, 'raddr') and conn.raddr and
                        conn.laddr.port in self.monitor_ports):
                        connection_key = f"{conn.laddr.ip}:{conn.laddr.port}-{conn.raddr.ip}:{conn.raddr.port}"
                        current_connections.add(connection_key)
                        
                        # 检测新连接
                        if connection_key not in self.network_connections:
                            self.log_event({
                                'type': 'network',
                                'severity': 'medium',
                                'message': f'检测到新网络连接: {conn.laddr.ip}:{conn.laddr.port} -> {conn.raddr.ip}:{conn.raddr.port}',
                                'details': {
                                    'local_ip': conn.laddr.ip,
                                    'local_port': conn.laddr.port,
                                    'remote_ip': conn.raddr.ip,
                                    'remote_port': conn.raddr.port,
                                    'protocol': 'tcp'
                                }
                            })
                
                # 检测断开的连接
                for old_conn in self.network_connections - current_connections:
                    self.log_event({
                        'type': 'network',
                        'severity': 'low',
                        'message': f'网络连接断开: {old_conn}',
                        'details': {'connection': old_conn, 'status': 'disconnected'}
                    })
                
                self.network_connections = current_connections
                time.sleep(2)  # 每2秒检查一次
                
            except Exception as e:
                print(f"网络监控错误: {e}")
                time.sleep(5)
    
    def system_monitor(self):
        """系统信息监控"""
        while True:
            try:
                # CPU使用率
                cpu_percent = psutil.cpu_percent(interval=1)
                if cpu_percent > 80:
                    self.log_event({
                        'type': 'system',
                        'severity': 'medium',
                        'message': f'CPU使用率过高: {cpu_percent}%',
                        'details': {'cpu_percent': cpu_percent, 'metric': 'cpu_usage'}
                    })
                
                # 内存使用率
                memory = psutil.virtual_memory()
                if memory.percent > 80:
                    self.log_event({
                        'type': 'system',
                        'severity': 'medium',
                        'message': f'内存使用率过高: {memory.percent}%',
                        'details': {'memory_percent': memory.percent, 'metric': 'memory_usage'}
                    })
                
                # 磁盘使用率
                disk = psutil.disk_usage('/')
                disk_percent = (disk.used / disk.total) * 100
                if disk_percent > 90:
                    self.log_event({
                        'type': 'system',
                        'severity': 'high',
                        'message': f'磁盘空间不足: {disk_percent:.1f}%',
                        'details': {'disk_percent': disk_percent, 'metric': 'disk_usage'}
                    })
                
                time.sleep(30)  # 每30秒检查一次
                
            except Exception as e:
                print(f"系统监控错误: {e}")
                time.sleep(10)
    
    def log_sender(self):
        """日志发送器"""
        while True:
            try:
                with self.queue_lock:
                    if len(self.log_queue) >= self.config.get('batch_size', 10):
                        logs_to_send = self.log_queue[:self.config.get('batch_size', 10)]
                        self.log_queue = self.log_queue[self.config.get('batch_size', 10):]
                    else:
                        logs_to_send = []
                
                if logs_to_send:
                    self.send_logs(logs_to_send)
                
                time.sleep(self.config.get('send_interval', 3))
                
            except Exception as e:
                print(f"日志发送错误: {e}")
                time.sleep(5)
    
    def send_logs(self, logs):
        """发送日志到平台"""
        try:
            platform_url = self.config.get('platform_url')
            if not platform_url:
                return
            
            # 直接发送所有日志，不进行时间过滤
            filtered_logs = logs  # 直接使用传入的日志
            
            if not filtered_logs:
                print("没有日志需要发送")
                return
            
            payload = {
                'target_id': self.config.get('target_id'),
                'target_name': self.config.get('target_name'),
                'target_ip': self.config.get('target_ip'),
                'logs': filtered_logs,
                'timestamp': datetime.now().isoformat()
            }
            
            # 添加调试输出
            print(f"准备发送 {len(filtered_logs)} 条日志到平台:")
            for i, log in enumerate(filtered_logs):
                log_time = log.get('timestamp', '无时间')
                print(f"日志 {i+1}: 时间={log_time}, 类型={log.get('type')}, 消息='{log.get('message')}', "
                    f"严重程度={log.get('severity')}, 源IP={log.get('details', {}).get('source_ip', 'N/A')}")
            
            response = requests.post(
                platform_url,
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            print(f"平台响应: HTTP {response.status_code}, {response.text}")
            
            if response.status_code != 200:
                print(f"发送日志失败: HTTP {response.status_code}")
                # 发送失败，将日志放回队列
                with self.queue_lock:
                    self.log_queue.extend(logs)
            
        except requests.RequestException as e:
            print(f"发送日志请求失败: {e}")
            # 发送失败，将日志放回队列
            with self.queue_lock:
                self.log_queue.extend(logs)
        except Exception as e:
            print(f"发送日志错误: {e}")



    def run(self):
        """运行Agent"""
        print(f"日志收集Agent启动 - 目标: {self.config.get('target_name')}")
        print(f"平台地址: {self.config.get('platform_url')}")
        print(f"发送间隔: {self.config.get('send_interval')}秒")
        print(f"批次大小: {self.config.get('batch_size')}条")
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nAgent停止运行")
            if hasattr(self, 'observer'):
                self.observer.stop()
                self.observer.join()

if __name__ == '__main__':
    agent = LogAgent()
    agent.run()