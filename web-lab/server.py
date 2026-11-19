"""웹 테스트 화면 서버: 챕터 목록을 보여 주고, 버튼을 누르면 정해진 테스트를 실제로 실행해 결과를 JSON으로 돌려준다."""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from chapters import Chapter, Test, chapters
from runner import Ctx, Run, TestError

HERE = Path(__file__).resolve().parent
MAX_BODY = 64 * 1024
HEX_RE = re.compile(r"^[0-9a-fA-F:\s]+$")


class LabServer(ThreadingHTTPServer):
    """테스트 정의와 실행 환경을 가진 서버. 테스트는 포트가 겹치므로 한 번에 하나만 돌린다."""

    def __init__(self, address: tuple[str, int], ctx: Ctx) -> None:
        super().__init__(address, Handler)
        self.ctx = ctx
        self.chapters: list[Chapter] = chapters()
        self.tests: dict[str, Test] = {t.id: t for c in self.chapters for t in c.tests}
        self.busy = threading.Lock()


def run_test(ctx: Ctx, test: Test) -> dict:
    """테스트 하나를 실행하고 화면에 보낼 결과 사전을 만든다."""
    run = Run(ctx)
    started = time.time()
    error = None
    try:
        test.func(ctx, run)
    except TestError as e:
        error = str(e)
    except Exception:  # 예상 못 한 오류도 숨기지 않고 화면에 그대로 보여 준다
        error = "예상하지 못한 오류:\n" + traceback.format_exc()
    statuses = [c["status"] for c in run.checks]
    return {
        "test": test.id,
        "ok": error is None and "fail" not in statuses,
        "error": error,
        "seconds": round(time.time() - started, 1),
        "checks": run.checks,
        "steps": run.steps,
        "tables": run.tables,
        "look": test.look,
    }


class Handler(BaseHTTPRequestHandler):
    """/, /api/chapters, /api/run/<id>, /api/dissect 를 처리한다."""

    server: LabServer

    def log_message(self, format: str, *args: object) -> None:
        print(f"[web-lab] {format % args}")

    def send_json(self, status: int, data: object) -> None:
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def allowed(self) -> bool:
        """내 PC의 이 서버 주소로 온 요청만 받는다(다른 사이트가 브라우저를 통해 테스트를 실행하지 못하게)."""
        port = self.server.server_address[1]
        hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
        if self.headers.get("Host") not in hosts:
            return False
        origin = self.headers.get("Origin")
        return origin is None or origin in {f"http://{h}" for h in hosts}

    def do_GET(self) -> None:
        if not self.allowed():
            self.send_json(403, {"error": "허용되지 않은 주소"})
        elif self.path in ("/", "/index.html"):
            body = (HERE / "index.html").read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/api/chapters":
            data = []
            for c in self.server.chapters:
                item = asdict(c)
                item["tests"] = [{k: v for k, v in asdict(t).items() if k != "func"} for t in c.tests]
                data.append(item)
            self.send_json(200, data)
        else:
            self.send_json(404, {"error": "없는 경로"})

    def read_json(self) -> dict:
        raw = self.headers.get("Content-Length", "0")
        if not raw.isdigit() or int(raw) > MAX_BODY:
            raise ValueError("본문 길이가 잘못됐습니다")
        body = self.rfile.read(int(raw)) if int(raw) else b"{}"
        data = json.loads(body)
        if not isinstance(data, dict):
            raise ValueError("JSON 객체가 아닙니다")
        return data

    def do_POST(self) -> None:
        if not self.allowed():
            self.send_json(403, {"error": "허용되지 않은 주소"})
            return
        if self.path.startswith("/api/run/"):
            test = self.server.tests.get(self.path.removeprefix("/api/run/"))
            if test is None:
                self.send_json(404, {"error": "없는 테스트"})
                return
            if not self.server.busy.acquire(blocking=False):
                self.send_json(409, {"error": "다른 테스트가 실행 중입니다. 끝난 뒤 다시 눌러 주세요."})
                return
            try:
                result = run_test(self.server.ctx, test)
            finally:
                self.server.busy.release()
            self.send_json(200, result)
        elif self.path == "/api/shutdown":
            killed, stuck = self.server.ctx.cleanup()
            self.send_json(200, {"ok": not stuck, "killed": killed, "stuck": stuck})
            # 응답을 보낸 뒤 서버 루프를 멈춘다. serve_forever를 돌리는 스레드와 다른 스레드에서 불러야 한다.
            threading.Thread(target=self.server.shutdown, daemon=True).start()
        elif self.path == "/api/dissect":
            try:
                data = self.read_json()
            except (ValueError, json.JSONDecodeError) as e:
                self.send_json(400, {"error": str(e)})
                return
            hex_text, link = data.get("hex", ""), data.get("link", "ethernet")
            if not isinstance(hex_text, str) or not HEX_RE.match(hex_text) or link not in ("ethernet", "null"):
                self.send_json(400, {"error": "16진수 문자열과 link(ethernet 또는 null)가 필요합니다"})
                return
            script = self.server.ctx.repo / "09-encapsulation" / "dissect.py"
            proc = subprocess.run([self.server.ctx.python, str(script), "--link", link, hex_text],
                                  capture_output=True, timeout=30, env={**os.environ, "PYTHONIOENCODING": "utf-8"})
            self.send_json(200, {"ok": proc.returncode == 0,
                                 "output": (proc.stdout + proc.stderr).decode("utf-8", errors="replace")})
        else:
            self.send_json(404, {"error": "없는 경로"})


def find_wireshark_dir(given: str | None) -> Path:
    """tshark.exe와 dumpcap.exe가 있는 Wireshark 설치 폴더를 찾는다. 인자 → PATH → 기본 설치 경로 순서."""
    on_path = shutil.which("tshark")
    candidates = [given, str(Path(on_path).parent) if on_path else None, r"C:\Program Files\Wireshark"]
    for c in candidates:
        if c and (Path(c) / "tshark.exe").exists() and (Path(c) / "dumpcap.exe").exists():
            return Path(c)
    raise SystemExit("Wireshark(tshark.exe, dumpcap.exe)를 찾지 못했습니다. "
                     "설치하거나 --wireshark-dir로 폴더를 알려 주세요 (00-setup 참고).")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--wireshark-dir", help="tshark.exe·dumpcap.exe가 있는 폴더 (기본: 자동으로 찾음)")
    parser.add_argument("--internet-if", help="인터넷 캡처에 쓸 어댑터 이름 (기본: 자동으로 찾음, 예: Wi-Fi)")
    args = parser.parse_args()

    ws = find_wireshark_dir(args.wireshark_dir)
    workdir = Path(tempfile.mkdtemp(prefix="web-lab-"))
    ctx = Ctx(repo=HERE.parent, python=sys.executable, tshark=ws / "tshark.exe", dumpcap=ws / "dumpcap.exe",
              workdir=workdir, internet_if=args.internet_if)
    server = LabServer(("127.0.0.1", args.port), ctx)
    print(f"[web-lab] http://127.0.0.1:{args.port}/ 를 브라우저로 여세요")
    print("[web-lab] 끝낼 때: 이 터미널에서 Ctrl+C, 또는 화면 오른쪽 위의 '서버 종료' 버튼")
    print(f"[web-lab] 캡처 파일과 임시 파일(종료할 때 지움): {workdir}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[web-lab] Ctrl+C를 받았습니다")
    finally:
        server.server_close()
        killed, stuck = ctx.cleanup()
        if killed:
            print(f"[web-lab] 실행 중이던 테스트 프로그램 {len(killed)}개를 끝냈습니다 (PID {killed})")
        if stuck:
            print(f"[web-lab] 경고: 끝나지 않은 프로그램이 있습니다 (PID {stuck}). "
                  "보안 프로그램 알림 창에 응답하거나 PC를 재시작하면 정리됩니다.")
        # TLS 키 파일(sslkeys.txt)도 여기 있으므로 남기지 않는다
        try:
            shutil.rmtree(workdir)
            print("[web-lab] 임시 파일을 지웠습니다.")
        except OSError as e:
            print(f"[web-lab] 경고: 임시 폴더를 다 지우지 못했습니다: {workdir} ({e})")
        print("[web-lab] 종료했습니다." + ("" if stuck else " 테스트가 띄운 프로그램은 모두 끝났습니다."))


if __name__ == "__main__":
    main()
