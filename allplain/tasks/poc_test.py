import os
import re
import subprocess
import time
from termcolor import colored


class POCTest:
    def __init__(self, target, payload_path):
        self.target = target
        self.payload_path = payload_path
        self.vuln_name = self.extract_vuln_name()

    def extract_vuln_name(self):
        """从payload路径中提取漏洞名称"""
        # 尝试从路径中提取漏洞名称
        filename = os.path.basename(self.payload_path)
        # 移除文件扩展名
        if '.' in filename:
            filename = filename.split('.')[0]

        # 尝试从路径中获取更多信息
        dir_parts = self.payload_path.split(os.sep)
        if len(dir_parts) > 1:
            # 使用目录名作为漏洞类型
            vuln_type = dir_parts[-2] if len(dir_parts) >= 2 else "unknown"
            return f"{vuln_type}/{filename}"
        return filename

    def run(self):
        print(colored("[*] poc test...", "blue"))

        # 检查POC文件是否存在
        if not os.path.exists(self.payload_path):
            print(colored(f"[-] POC file not found: {self.payload_path}", "red"))
            return

        try:
            # 执行POC脚本
            start_time = time.time()
            result = subprocess.run(
                ["python", self.payload_path, self.target],
                capture_output=True,
                text=True,
                timeout=120
            )
            elapsed = time.time() - start_time

            # 检查执行结果
            if result.returncode == 0:
                # 检查输出中是否有成功标志
                if re.search(r"(vulnerable|success|exploited)", result.stdout, re.I):
                    status = colored("[+]", "blue")
                    status_text = "Vulnerable"
                else:
                    status = colored("[-]", "red")
                    status_text = "Not Vulnerable"
            else:
                status = colored("[-]", "red")
                status_text = "Execution Failed"

            # 输出结果
            print("{} target={}, vulnerability name={}, poc={}, status={}".format(
                status, self.target, self.vuln_name, os.path.basename(self.payload_path), status_text
            ))
            print(f"Execution time: {elapsed:.2f} seconds")

            # 显示POC输出
            if result.stdout.strip():
                print("\nPOC Output:")
                print(result.stdout)

            if result.stderr.strip():
                print(colored("\nError Output:", "yellow"))
                print(result.stderr)

        except subprocess.TimeoutExpired:
            print(colored("[-] POC test timed out for {}".format(self.payload_path), "red"))
        except Exception as e:
            print(colored("[-] Error executing POC: {}".format(str(e)), "red"))