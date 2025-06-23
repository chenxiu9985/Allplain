import concurrent.futures
import platform
import subprocess
from tasks.base import ScanTask
from termcolor import colored

class AliveScan(ScanTask):
    def ping(self, ip):
        cmd = ['ping', '-n' if platform.system() == 'Windows' else '-c', '1', ip]
        result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if result.returncode == 0:
            print(colored("[+]", "blue"), f"{ip} is alive")

        else:
            print(colored("[-]", "red"), f"{ip} is unreachable")


    def run(self):
        print(colored(f"[*] Running host discovery...", "blue"))
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            executor.map(self.ping, self.targets)
