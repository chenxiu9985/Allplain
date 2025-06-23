import re
import socket
import sys
import threading
from queue import Queue
from termcolor import colored
import time
import ssl
from collections import defaultdict
import binascii
from tasks.base import ScanTask
from threading import Event


class ServiceScanTaskGroup(ScanTask):
    def __init__(self, targets, mode="light", threads=100, timeout=3):
        self.targets = targets
        self.mode = mode
        self.threads = threads
        self.timeout = timeout
        self.lock = threading.Lock()
        self.results = defaultdict(dict)

        # 存储探针和匹配规则
        self.probes = {}
        self.match_patterns = defaultdict(list)
        self.ports_info = {'tcp': [], 'udp': []}
        self.ssl_ports = set()
        self.probe_fallbacks = {}  # 探针的fallback链

        # 加载数据文件
        self.load_service_probes("dependent_files/nmap-service-probes")
        self.load_nmap_services("dependent_files/nmap-services")

        # 中断事件
        self.stop_event = Event()

    def load_service_probes(self, path):
        """加载并解析nmap-service-probes文件"""
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except FileNotFoundError:
            print(colored(f"[-] nmap-service-probes file not found at {path}", "red"))
            sys.exit(0)

        # 解析全局SSL端口
        ssl_m = re.search(r'(?m)^sslports\s+([0-9,\-\s]+)', content)
        if ssl_m:
            self.ssl_ports = set(self.parse_port_range(ssl_m.group(1)))

        # 解析探针块
        probe_blocks = re.split(r'(?m)^Probe ', content)
        for block in probe_blocks[1:]:  # 跳过第一个空块
            lines = block.splitlines()
            if not lines:
                continue

            # 解析探针头
            header = lines[0].strip()
            match = re.match(r'^(TCP|UDP)\s+(\w+)\s+q\|([^\|]+)\|', header)
            if not match:
                continue

            proto, name, payload_str = match.groups()
            try:
                # 转换payload中的转义序列
                payload = binascii.unhexlify(payload_str) if re.match(r'^[0-9a-fA-F]+$',
                                                                      payload_str) else payload_str.encode('latin1')
                payload = payload.decode('unicode_escape').encode('latin1')
            except:
                payload = payload_str.encode('latin1')

            # 解析探针属性
            rarity = 6
            totalwaitms = 6000
            tcpwrappedms = 2000
            fallbacks = []
            ports = []
            sslports = []
            matches = []
            softmatches = []

            for line in lines[1:]:
                line = line.strip()
                if line.startswith('rarity '):
                    rarity = int(line.split()[1])
                elif line.startswith('totalwaitms '):
                    totalwaitms = int(line.split()[1])
                elif line.startswith('tcpwrappedms '):
                    tcpwrappedms = int(line.split()[1])
                elif line.startswith('fallback '):
                    fallbacks = line.split()[1:]
                elif line.startswith('ports '):
                    ports = self.parse_port_range(line.split()[1])
                elif line.startswith('sslports '):
                    sslports = self.parse_port_range(line.split()[1])
                elif line.startswith('match '):
                    match_info = self.parse_match_line(line, 'match')
                    if match_info:
                        matches.append(match_info)
                elif line.startswith('softmatch '):
                    match_info = self.parse_match_line(line, 'softmatch')
                    if match_info:
                        softmatches.append(match_info)

            # 存储探针
            self.probes[name] = {
                'protocol': proto.lower(),
                'name': name,
                'payload': payload,
                'rarity': rarity,
                'totalwaitms': totalwaitms,
                'tcpwrappedms': tcpwrappedms,
                'fallbacks': fallbacks,
                'ports': ports,
                'sslports': sslports,
                'matches': matches,
                'softmatches': softmatches
            }

            # 存储匹配规则
            self.match_patterns[name] = matches + softmatches

            # 存储fallback链
            self.probe_fallbacks[name] = [name] + fallbacks + (['NULL'] if proto.lower() == 'tcp' else [])

    def parse_match_line(self, line, match_type):
        """解析match/softmatch行"""
        pattern = r'(?:match|softmatch)\s+(\S+)\s+m(?P<delim>.)(.*?)(?P=delim)([is]*)\s*(.*)'
        match = re.search(pattern, line)
        if not match:
            return None

        service, regex_str, flags, templates = match.group(1), match.group(3), match.group(4), match.group(5)

        # 解析正则标志
        re_flags = 0
        if 'i' in flags: re_flags |= re.IGNORECASE
        if 's' in flags: re_flags |= re.DOTALL

        try:
            regex = re.compile(regex_str.encode(), re_flags)
        except:
            return None

        # 解析模板
        template_dict = {}
        template_pattern = r'([pviho]|cpe)/([^/]+)/'
        for tmpl_match in re.finditer(template_pattern, templates):
            key, value = tmpl_match.groups()
            template_dict[key] = value

        return {
            'service': service,
            'pattern': regex,
            'match_type': match_type,
            'templates': template_dict,
            'pattern_length': len(regex_str)
        }

    def parse_port_range(self, port_range):
        """解析端口范围字符串"""
        ports = []
        parts = port_range.split(',')
        for part in parts:
            part = part.strip()
            if '-' in part:
                start, end = part.split('-')
                ports.extend(range(int(start), int(end) + 1))
            elif part:
                ports.append(int(part))
        return ports

    def load_nmap_services(self, path):
        """加载nmap-services文件"""
        try:
            with open(path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    parts = line.split()
                    if len(parts) < 3:
                        continue

                    service_name = parts[0]
                    port_proto = parts[1]
                    frequency = float(parts[2])

                    if '/' in port_proto:
                        port, proto = port_proto.split('/')
                        port = int(port)
                        proto = proto.lower()
                        if proto in ['tcp', 'udp']:
                            self.ports_info[proto].append((port, frequency, service_name))
        except FileNotFoundError:
            print(colored(f"[-] nmap-services file not found at {path}", "red"))
            sys.exit(0)

        for proto in self.ports_info:
            self.ports_info[proto].sort(key=lambda x: x[1], reverse=True)

    def get_ports_to_scan(self, protocol):
        """根据模式和协议获取要扫描的端口列表"""
        if self.mode == "light":
            num_ports = 100
        else:
            num_ports = 1000

        ports = [port for port, _, _ in self.ports_info[protocol][:num_ports]]
        return ports

    def scan_port(self, target, port, protocol):
        """扫描目标主机的指定端口"""
        # 创建扫描任务
        task = ServiceScanTask(self, target, port, protocol)
        return task.run()

    def send_probe(self, target, port, protocol, probe, ssl_wrap=False):
        """发送单个探针并获取响应"""
        try:
            if protocol == 'tcp':
                # 创建原始套接字
                raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                raw_sock.settimeout(self.timeout)
                raw_sock.connect((target, port))

                # SSL包装
                sock = raw_sock
                if ssl_wrap:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    sock = context.wrap_socket(raw_sock, server_hostname=target)
                    sock.settimeout(self.timeout)

                # 发送探针
                if probe and probe.get('payload'):
                    sock.sendall(probe['payload'])

                # 接收响应
                response = b''
                start_time = time.time()
                timeout = probe.get('totalwaitms', 6000) / 1000 if probe else self.timeout

                while time.time() - start_time < timeout:
                    try:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        response += chunk
                    except (socket.timeout, ssl.SSLWantReadError):
                        # 非阻塞读取或超时
                        break
                    except:
                        break

                # 关闭连接
                sock.close()
                return response

            elif protocol == 'udp':
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.timeout)

                if probe and probe.get('payload'):
                    sock.sendto(probe['payload'], (target, port))
                else:
                    sock.sendto(b'', (target, port))

                try:
                    response, _ = sock.recvfrom(4096)
                    return response
                except socket.timeout:
                    return None
                finally:
                    sock.close()

        except Exception as e:
            return None
        return None

    def match_response(self, probe_name, response):
        """调用服务匹配"""
        patterns = self.match_patterns.get(probe_name, [])
        return self.nmap_style_match(response, patterns)

    def nmap_style_match(self, response, patterns):
        """Nmap风格的服务匹配"""
        best_match = None

        # 1. 首先尝试所有硬匹配规则（按顺序）
        for pattern in patterns:
            if pattern['match_type'] != 'match':
                continue

            match = pattern['pattern'].search(response)
            if match:
                service_info = self.apply_templates(pattern, match, response)
                # 硬匹配立即返回
                return {
                    'service': service_info,
                    'confidence': 'hard',
                    'probe': pattern
                }

        # 2. 尝试软匹配规则
        for pattern in patterns:
            if pattern['match_type'] != 'softmatch':
                continue

            match = pattern['pattern'].search(response)
            if match:
                service_info = self.apply_templates(pattern, match, response)
                # 保留第一个软匹配
                if not best_match:
                    best_match = {
                        'service': service_info,
                        'confidence': 'soft',
                        'probe': pattern
                    }

        return best_match

    def apply_templates(self, pattern, match, response):
        """应用模板替换 - 添加变量替换逻辑"""
        # 提取基础服务名
        base_service = pattern['service']
        templates = pattern.get('templates', {})
        product = templates.get('p', '')
        version = templates.get('v', '')

        # 获取匹配对象
        match_obj = pattern['pattern'].search(response)
        if match_obj:
            # 替换模板中的变量（$1, $2 等）
            product = self.replace_template_vars(product, match_obj)
            version = self.replace_template_vars(version, match_obj)

        # 返回分开的字段
        return {
            'base_service': base_service,
            'product': product,
            'version': version,
        }

    def replace_template_vars(self, template, match_obj):
        """替换模板中的变量（$1, $2 等）为实际匹配值"""
        if not template:
            return ""

        # 替换 $1, $2, ..., $9
        for i in range(1, 10):
            try:
                # 检查该组是否存在
                if match_obj.group(i):
                    # 将字节串转换为字符串
                    try:
                        group_str = match_obj.group(i).decode('utf-8', errors='replace')
                    except:
                        group_str = match_obj.group(i).decode('latin1', errors='replace')

                    template = template.replace(f'${i}', group_str)
            except IndexError:
                # 该组不存在，跳过
                pass

        return template

    def worker(self, queue):
        """工作线程函数"""
        while not self.stop_event.is_set():
            try:
                task = queue.get(timeout=1)  # 添加 timeout 避免永久阻塞
            except:
                break  # 如果队列为空或超时，退出线程

            target = task['target']
            port = task['port']
            protocol = task['protocol']

            try:
                result = self.scan_port(target, port, protocol)
                if result:
                    with self.lock:
                        self.results[target][(port, protocol)] = result
            finally:
                queue.task_done()

    def run(self):
        """执行版本探测"""
        start_time = time.time()
        print(colored("[*] Starting version detection...", "blue"))

        queue = Queue()
        for target in self.targets:
            print(colored(f"[+] Scanning {target}", "green"))

            tcp_ports = self.get_ports_to_scan('tcp')
            udp_ports = self.get_ports_to_scan('udp') if self.mode == "all" else []

            for port in tcp_ports:
                queue.put({'target': target, 'port': port, 'protocol': 'tcp'})

            for port in udp_ports:
                queue.put({'target': target, 'port': port, 'protocol': 'udp'})

        threads = []
        for _ in range(min(self.threads, queue.qsize() or 1)):
            t = threading.Thread(target=self.worker, args=(queue,))
            t.daemon = True
            t.start()
            threads.append(t)

        queue.join()
        self.print_results()

        duration = time.time() - start_time
        print(colored(f"\n[*] Version detection completed in {duration:.2f} seconds", "blue"))

    def print_results(self):
        """格式化输出版本探测结果"""
        # 创建一个集合来存储所有检测到的服务版本
        detected_services = set()

        print(colored("\n[*] Version Detection Results:", "blue"))

        for target, ports in self.results.items():
            print(colored(f"\n[+] Target: {target}", "yellow"))

            if not ports:
                print("    " + colored("[-]", "red") + " no services detected")
                continue

            # 准备格式化数据
            formatted = []
            for (port, proto), info in ports.items():
                port_str = f"{port}/{proto}"
                state = "open"

                # 获取服务名和版本信息
                service_name = info['service'].get('base_service', 'unknown')
                version = info['service'].get('version', '')
                product = info['service'].get('product', '')

                # 构造服务版本字符串
                service_version = f"{product} {version}".strip()
                if service_version:
                    detected_services.add(service_version)

                formatted.append((port_str, state, service_name, product + " " + version))

            # 计算每列最大宽度
            max_port_len = max(len(row[0]) for row in formatted) if formatted else 0
            max_service_len = max(len(row[2]) for row in formatted) if formatted else 0
            max_version_len = max(len(row[3]) for row in formatted) if formatted else 0

            # 打印表头
            header = f"{'PORT'.ljust(max_port_len)}   {'STATE'}    {'SERVICE'.ljust(max_service_len)}   {'VERSION'.ljust(max_version_len)}"
            print("    " + header)

            # 打印分隔线
            separator = "-" * (max_port_len + max_service_len + max_version_len + 18)
            print("    " + separator)

            # 打印每一行
            for port_str, state, service_name, version_info in formatted:
                line = f"{port_str.ljust(max_port_len)}   {state}     {service_name.ljust(max_service_len)}      {version_info.ljust(max_version_len)}"
                print("    " + line)


class ServiceScanTask:
    def __init__(self, scanner, target, port, protocol):
        self.scanner = scanner
        self.target = target
        self.port = port
        self.protocol = protocol
        self.accumulated_response = b""
        self.ssl_detected = False
        self.current_probe_chain = []
        self.soft_match = None

    def run(self):
        """执行服务扫描任务"""
        # 初始化探针链
        self.current_probe_chain = self.select_probe_chain()

        # 执行探针链
        for probe_name in self.current_probe_chain:
            probe = self.scanner.probes.get(probe_name)
            if not probe:
                continue

            # 发送探针（NULL探针除外）
            ssl_wrap = self.ssl_detected
            response = self.scanner.send_probe(self.target, self.port, self.protocol, probe, ssl_wrap)

            if response:
                # 累积响应
                self.accumulated_response += response

                # 尝试匹配
                result = self.try_match(probe_name)

                # SSL隧道检测
                if result and self.check_ssl_service(result):
                    self.ssl_detected = True
                    self.reset_for_ssl()
                    continue  # 重新开始探针链

                # 结果处理
                if result:
                    if result['confidence'] == 'hard':
                        # 添加 SSL 前缀（如果需要）
                        if self.ssl_detected:
                            self.add_ssl_prefix(result['service'])
                        return result  # 硬匹配终止探针链
                    elif not self.soft_match:  # 保留第一个软匹配
                        self.soft_match = result

        # 返回最佳匹配结果
        if self.soft_match:
            # 添加 SSL 前缀（如果需要）
            if self.ssl_detected:
                self.add_ssl_prefix(self.soft_match['service'])
            return self.soft_match
        return None

    def add_ssl_prefix(self, service_dict):
        """给服务名添加 SSL 前缀"""
        base_service = service_dict.get('base_service', '')
        if not base_service.startswith('ssl/') and not base_service.startswith('https'):
            service_dict['base_service'] = 'ssl/' + base_service

    def check_ssl_service(self, result):
        """检查是否为SSL服务"""
        service = result['service'].get('base_service', '').lower()
        return 'ssl' in service or 'tls' in service or 'https' in service

    def reset_for_ssl(self):
        """重置状态以进行SSL扫描"""
        self.accumulated_response = b""
        self.current_probe_chain = self.select_probe_chain()
        self.soft_match = None

    def select_probe_chain(self):
        """选择探针链"""
        # 1. 总是以NULL探针开始
        chain = ['NULL']

        # 2. 添加端口特定探针
        for probe_name, probe_data in self.scanner.probes.items():
            if (probe_data['protocol'] == self.protocol and
                    (self.port in probe_data['ports'] or
                     (self.ssl_detected and self.port in probe_data['sslports']))):
                chain.append(probe_name)

        # 3. 添加通用探针
        chain.extend(['GenericLines', 'GetRequest', 'HTTPOptions'])

        return chain

    def try_match(self, probe_name):
        """尝试匹配响应"""
        # 获取当前探针及其fallback链
        probe_chain = self.scanner.probe_fallbacks.get(probe_name, [probe_name])

        for p_name in probe_chain:
            result = self.scanner.match_response(p_name, self.accumulated_response)
            if result:
                return result
        return None