import os
import csv
import time
import re
from termcolor import colored


def compare_versions(target, base):
    """比较两个版本号"""
    target_parts = list(map(int, target.split('.')))
    base_parts = list(map(int, base.split('.')))

    # 补零使长度一致
    while len(target_parts) < len(base_parts):
        target_parts.append(0)
    while len(base_parts) < len(target_parts):
        base_parts.append(0)

    return target_parts, base_parts


class SearchSploit:
    def __init__(self):
        self.csv_file = "dependent_files/files_exploits.csv"
        self.exploitdb_path = "dependent_files"

    def version_in_range(self, target_version, version_range):
        """检查目标版本是否在指定的版本范围内"""
        version_range = re.sub(r'[^\d<>=., ]', '', version_range)
        conditions = re.split(r'[;,/]', version_range)

        for condition in conditions:
            condition = condition.strip()
            if not condition:
                continue

            match = re.match(r'([<>]=?)?\s*([\d.]+)', condition)
            if not match:
                continue

            op, version = match.groups()
            op = op or '='

            # 使用统一的版本比较逻辑
            target_parts, check_parts = compare_versions(target_version, version)

            if op == '<':
                if target_parts >= check_parts:
                    return False
            elif op == '<=':
                if target_parts > check_parts:
                    return False
            elif op == '>':
                if target_parts <= check_parts:
                    return False
            elif op == '>=':
                if target_parts < check_parts:
                    return False
            elif op == '=':
                if target_parts != check_parts:
                    return False

        return True

    def clean_title(self, title):
        """清理标题，在第一个破折号处截断"""
        dash_index = title.find('-')
        return title[:dash_index].strip() if dash_index != -1 else title

    def search(self, query):
        start_time = time.time()
        print(colored("[*] Searching exploits...", "blue"))

        if not os.path.exists(self.csv_file):
            print(colored(f"[-] ExploitDB database not found at: {self.csv_file}", "red"))
            print(colored("[!] Please ensure exploitdb directory is in the project root", "yellow"))
            return

        version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', query)
        target_version = version_match.group(1) if version_match else None
        base_query = re.sub(r'\d+\.\d+(?:\.\d+)?', '', query).strip()

        results = []

        try:
            with open(self.csv_file, "r", encoding="utf-8", errors="ignore") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    clean_title = self.clean_title(row["description"])
                    search_fields = [field.lower() for field in [row["description"], row["file"]]]

                    if any(base_query.lower() in field for field in search_fields):
                        if not target_version:
                            results.append({"title": clean_title, "path": row["file"]})
                        else:
                            version_range_match = re.search(
                                r'([<>]=?)?\s*([\d.]+)\s*(?:/|;|,|or)\s*([<>]=?)?\s*([\d.]+)',
                                row["description"]
                            )

                            if version_range_match:
                                op1, ver1, op2, ver2 = version_range_match.groups()
                                version_range = f"{op1 or ''}{ver1} / {op2 or ''}{ver2}"

                                if self.version_in_range(target_version, version_range):
                                    results.append({"title": clean_title, "path": row["file"]})
                            elif target_version in row["description"]:
                                results.append({"title": clean_title, "path": row["file"]})

        except Exception as e:
            print(colored(f"[-] Error reading database: {str(e)}", "red"))
            return

        if results:
            if results:
                # 计算最大标题长度
                max_title_length = max(len(item["title"]) for item in results)
                max_path_length = max(len(os.path.join(self.exploitdb_path, item["path"])) for item in results)
                header_format = "{:<%d} {}" % (max_title_length + 4)  # 添加一些填充
                print("\n" + header_format.format("Exploit Title", "PoC Path"))
                print("-" * (max_title_length + max_path_length + 8))  # 调整分隔线长度

                for item in results:
                    title = item["title"]
                    full_path = os.path.join(self.exploitdb_path, item["path"])

                    print(header_format.format(title, full_path))
        else:
            print(colored(f"[-] No exploits found for '{query}'", "red"))

        elapsed = time.time() - start_time
        print(colored(f"\n[*] Search completed in {elapsed:.2f} seconds, found {len(results)} results", "blue"))
