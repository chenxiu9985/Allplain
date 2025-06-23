import asyncio
import time
import socket

import scapy.all as scapy
from termcolor import colored
from tasks.base import ScanTask


class PortScan(ScanTask):
    def __init__(self, targets, ports=None, thread_count=100):
        super().__init__(targets)
        self.thread_count = thread_count
        # 默认端口列表，可由上层传入
        self.ports = ports

    def _tcp_check(self, ip, port):
        pkt = scapy.IP(dst=ip) / scapy.TCP(dport=port, flags="S")
        response = scapy.sr1(pkt, timeout=1, verbose=0)
        if response and response.haslayer(scapy.TCP):
            if response[scapy.TCP].flags == 0x12:  # SYN+ACK
                scapy.send(scapy.IP(dst=ip)/scapy.TCP(dport=port, flags="R"), verbose=0)
                return "open"

    def _udp_check(self, ip, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(1)
                s.sendto(b"", (ip, port))
                data, _ = s.recvfrom(1024)
                if data:
                    return "open"
        except:
            return None

    async def scan_target(self, ip):
        start_time = time.time()
        print(colored("[*] Running port scan...", "blue"))
        print(colored("[+] Scanning " + ip, "yellow"))

        sem = asyncio.Semaphore(self.thread_count)
        results = []

        async def scan(protocol, check_fn, port):
            async with sem:
                state = await asyncio.to_thread(check_fn, ip, port)
                if state:
                    results.append((f"{port}/{protocol}", state))

        # 提交 TCP 和 UDP 扫描任务
        tasks = []
        for port in self.ports:
            tasks.append(scan("tcp", self._tcp_check, port))
            tasks.append(scan("udp", self._udp_check, port))

        await asyncio.gather(*tasks)

        # 计算最大列宽
        if not results:
            print("    " + colored("[-]", "red") + " no open ports detected")
            return

        max_col1 = max(len(item[0]) for item in results)
        header = f"{'PORT'.ljust(max_col1)}   STATE"
        print("    " + header)

        # 按端口排序输出
        for port_proto, state in sorted(results, key=lambda x: (int(x[0].split('/')[0]), x[0])):
            line = f"{port_proto.ljust(max_col1)}   {state}"
            print("    " + line)

        duration = time.time() - start_time
        print(colored(f"\n[*] Port scan completed in {duration:.2f} seconds\n", "blue"))

    def run(self):
        try:
            asyncio.run(self._run_all())
        except KeyboardInterrupt:
            print(colored("\n[!] Scan interrupted.", "red"))

    async def _run_all(self):
        for ip in self.targets:
            await self.scan_target(ip)
