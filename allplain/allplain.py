import argparse
import os
import sys

from tasks.alive import AliveScan
from tasks.port_scan import PortScan
from tasks.service_scan import ServiceScanTaskGroup
from tasks.searchsploit import SearchSploit
from tasks.poc_test import POCTest
from termcolor import colored


def load_targets_from_file(file_path):
    try:
        with open(file_path, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(colored(f"[-] Target file '{file_path}' not found!", "red"))
        return []


def parse_args():
    parser = argparse.ArgumentParser(description="Allplain Network Scanner")

    parser.add_argument("-alive", help="Perform host discovery (ping scan)", action="store_true")
    parser.add_argument("-port", help="Perform port scan, specify ports like 80,443 or 1-1024", type=str)
    parser.add_argument("-allports", help="Scan all ports (1-65535)", action="store_true")
    parser.add_argument("--version-light", action="store_true", help="Lightweight version detection")
    parser.add_argument("--version-all", action="store_true", help="Full version detection")
    parser.add_argument("-f", help="Specify target file (default: targets.txt)", type=str, default="targets.txt")
    parser.add_argument("-thread", help="Number of threads to use (default: 100)", type=int, default=100)
    parser.add_argument("ip", nargs="?", help="Optional single IP address (overrides -f file)")
    parser.add_argument("-searchsploit", nargs='+', help="Search for exploits by service name", metavar="SERVICE")
    parser.add_argument("--poc-test", help="Perform POC testing", action="store_true")
    parser.add_argument("-target", help="Target for POC testing (format: IP:PORT)", type=str)
    parser.add_argument("-payload", help="POC file name for testing", type=str)

    return parser.parse_args()


def main():
    args = parse_args()

    # 目标获取逻辑：优先使用命令行中的 IP，其次使用文件
    if args.ip:
        targets = [args.ip]
    else:
        targets = load_targets_from_file(args.f)

    if not targets:
        print(colored("[-] No valid targets found.", "red"))
        return

    # 1. 主机存活探测
    if args.alive:
        scanner = AliveScan(targets)
        scanner.run()

    # 2. 端口扫描（必须有 -port 或 -allports 之一）
    if args.port or args.allports:
        if args.port:
            ports = []
            for part in args.port.split(','):
                if '-' in part:
                    start, end = part.split('-')
                    ports.extend(range(int(start), int(end) + 1))
                else:
                    ports.append(int(part))
        elif args.allports:
            ports = list(range(1, 65536))
        else:
            print(colored("[-] Please specify ports with -port or use -allports.", "red"))
            return

        scanner = PortScan(targets, ports, args.thread)
        scanner.run()

    # 3. 资产版本探测
    if args.version_light:
        scanner = ServiceScanTaskGroup(targets, mode="light")
        scanner.run()
    elif args.version_all:
        scanner = ServiceScanTaskGroup(targets, mode="all")
        scanner.run()

    # 4.搜索漏洞poc
    if args.searchsploit:
        # 将多个参数合并为一个查询字符串
        query = " ".join(args.searchsploit)
        searcher = SearchSploit()
        searcher.search(query)

    # 5. poc测试
    if args.poc_test:
        if not args.target or not args.payload:
            print(colored("[-] Please specify both target and payload for POC testing.", "red"))
            return
        # 确保 payload 路径是有效的
        if not os.path.exists(args.payload):
            # 尝试在 exploitdb 目录下查找
            exploitdb_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "exploitdb")
            possible_path = os.path.join(exploitdb_path, args.payload)

            if os.path.exists(possible_path):
                args.payload = possible_path
            else:
                print(colored(f"[-] POC file not found: {args.payload}", "red"))
                return

        tester = POCTest(args.target, args.payload)
        tester.run()


if __name__ == "__main__":
    main()
