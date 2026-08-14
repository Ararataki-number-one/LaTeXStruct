# -*- coding: utf-8 -*-
"""主动更新链路 E2E 演示：启动本地 0.2.0 exe，轮询更新接口直到发现新版。"""

import subprocess
import sys
import time
import urllib.request
import json

EXE = r"C:\Users\ZQY\Desktop\deepseek\latexstruct\dist\LaTeXStruct.exe"
PORT = 8093


def main():
    proc = subprocess.Popen([EXE, "--server", "--port", str(PORT)])
    try:
        for i in range(30):  # 最多 5 分钟
            time.sleep(10)
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/api/update/check", timeout=10) as r:
                    info = json.loads(r.read().decode("utf-8"))
                print(
                    f"[{i}] current={info['current']} available={info['available']} "
                    f"latest={info['latest']} err={info['error'][:40]}",
                    flush=True,
                )
                if info["available"]:
                    print("E2E 成功：0.2.0 客户端检测到新版本", info["latest"], flush=True)
                    return 0
            except Exception as e:  # noqa: BLE001
                print(f"[{i}] 服务未就绪: {e}", flush=True)
        print("超时：未检测到更新", flush=True)
        return 1
    finally:
        proc.terminate()


if __name__ == "__main__":
    sys.exit(main())
