"""테스트 실행 도구: 명령 실행, 실습 서버 띄우기, tshark 캡처와 읽기, 확인 결과를 한 번의 실행(Run) 단위로 모은다."""

import codecs
import json
import os
import socket
import subprocess
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

LOOPBACK_IF = r"\Device\NPF_Loopback"


def console_encoding() -> str:
    """Windows 기본 명령(ping, arp 등)이 쓰는 콘솔 인코딩 이름을 반환한다."""
    try:
        codecs.lookup("oem")
        return "oem"
    except LookupError:
        return "utf-8"


class TestError(Exception):
    """테스트를 더 진행할 수 없을 때 쓰는 예외. 메시지가 화면에 그대로 나간다."""


def kill_tree(proc: subprocess.Popen) -> bool:
    """프로세스와 그 자식까지 모두 끝낸다. 10초 안에 끝나지 않으면 False를 반환한다(예외로 멈추지 않는다)."""
    if proc.poll() is None:
        subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)], capture_output=True)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            return False
    return True


@dataclass
class Network:
    """인터넷으로 나가는 어댑터 정보."""

    local_ip: str
    alias: str
    prefix: int
    gateway: str


@dataclass
class Ctx:
    """테스트가 공통으로 쓰는 경로와 환경."""

    repo: Path
    python: str
    tshark: Path  # 캡처 파일 읽기용
    dumpcap: Path  # 캡처용. tshark와 달리 extcap 보조 도구(Udpdump 등)를 실행하지 않는다
    workdir: Path
    internet_if: str | None = None  # None이면 처음 필요할 때 찾는다
    _network: Network | None = None
    live: set[subprocess.Popen] = field(default_factory=set)  # 테스트가 띄워서 아직 살아 있을 수 있는 프로세스

    def wireshark_env(self) -> dict[str, str]:
        """tshark·dumpcap용 환경 변수. extcap 폴더를 빈 폴더로 바꿔서 Udpdump 같은 보조 도구가 실행되지 않게 한다.

        tshark는 시작할 때 extcap 폴더의 도구를 모두 한 번씩 실행하는데, 이 PC의 V3가 그중
        Udpdump.exe 실행을 막고 사용자 응답을 기다리느라 tshark가 멈춘 적이 있다.
        """
        empty = self.workdir / "no-extcap"
        empty.mkdir(exist_ok=True)
        return {**os.environ, "WIRESHARK_EXTCAP_DIR": str(empty)}

    def spawn(self, args: list[str], **kwargs) -> subprocess.Popen:
        """프로세스를 띄우고 정리 대상 목록에 올린다."""
        proc = subprocess.Popen(args, **kwargs)
        self.live.add(proc)
        return proc

    def finish(self, proc: subprocess.Popen) -> bool:
        """프로세스(와 자식)를 끝내고 정리 대상 목록에서 뺀다. 끝나지 않았으면 목록에 남기고 False."""
        if kill_tree(proc):
            self.live.discard(proc)
            return True
        return False

    def cleanup(self) -> tuple[list[int], list[int]]:
        """살아 있는 테스트 프로세스를 모두 끝내고 (끝낸 PID, 끝내지 못한 PID)를 반환한다."""
        killed, stuck = [], []
        for proc in list(self.live):
            alive = proc.poll() is None
            if self.finish(proc):
                if alive:
                    killed.append(proc.pid)
            else:
                stuck.append(proc.pid)
        return killed, stuck

    def network(self) -> Network:
        """인터넷으로 나가는 어댑터의 IP, 이름, 서브넷 길이, 게이트웨이를 찾아 반환한다."""
        if self._network is None:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))  # UDP connect는 패킷을 보내지 않고 나갈 경로만 정한다
                local_ip = s.getsockname()[0]
            script = (
                f"$ip = Get-NetIPAddress -AddressFamily IPv4 | Where-Object IPAddress -eq '{local_ip}' | Select-Object -First 1; "
                "$r = Get-NetRoute -DestinationPrefix 0.0.0.0/0 -InterfaceIndex $ip.InterfaceIndex | Select-Object -First 1; "
                "@{alias=$ip.InterfaceAlias; prefix=$ip.PrefixLength; gateway=$r.NextHop} | ConvertTo-Json -Compress"
            )
            out = subprocess.run(
                ["powershell", "-NoProfile", "-Command", script],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30,
            )
            try:
                info = json.loads(out.stdout)
            except json.JSONDecodeError as e:
                raise TestError(f"네트워크 정보를 읽지 못했습니다: {out.stdout!r} {out.stderr!r}") from e
            if not info.get("alias") or not info.get("gateway"):
                raise TestError(f"인터넷 어댑터나 게이트웨이를 찾지 못했습니다: {info}")
            self._network = Network(local_ip, info["alias"], int(info["prefix"]), info["gateway"])
        return self._network

    def internet_interface(self) -> str:
        """tshark에 넘길 인터넷 어댑터 이름을 반환한다."""
        return self.internet_if or self.network().alias


@dataclass
class Run:
    """테스트 한 번의 기록: 실행한 단계, 표, 확인 결과."""

    ctx: Ctx
    steps: list[dict] = field(default_factory=list)
    tables: list[dict] = field(default_factory=list)
    checks: list[dict] = field(default_factory=list)

    # ---------- 명령 실행 ----------

    def cmd(self, label: str, args: list[str], *, timeout: float = 60, console: bool = False,
            cwd: Path | None = None, show: str | None = None) -> str:
        """명령을 실행하고 표준출력+표준에러를 합친 문자열을 반환한다. 단계 기록에 남긴다."""
        env = {**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"}
        try:
            proc = subprocess.run(
                args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, cwd=cwd, env=env,
            )
        except subprocess.TimeoutExpired as e:
            raise TestError(f"'{label}' 명령이 {timeout}초 안에 끝나지 않았습니다") from e
        output = proc.stdout.decode(console_encoding() if console else "utf-8", errors="replace")
        self.steps.append({"label": label, "command": show or self.pretty(args), "output": output.rstrip()})
        return output

    def py(self, label: str, script: Path, *args: str, timeout: float = 60) -> str:
        """실습 폴더의 Python 스크립트를 실행한다."""
        return self.cmd(label, [self.ctx.python, str(script), *args], timeout=timeout, cwd=script.parent,
                        show=self.pretty(["python", script.name, *args]))

    def note(self, label: str, text: str) -> None:
        """명령 없이 설명만 단계 기록에 남긴다."""
        self.steps.append({"label": label, "command": "", "output": text})

    def pretty(self, args: list[str]) -> str:
        """화면에 보여 줄 명령 문자열을 만든다. 긴 경로는 파일 이름만 남긴다."""
        shown = []
        for a in args:
            p = Path(a)
            if p.is_absolute() and p.exists():
                a = p.name
            shown.append(f'"{a}"' if " " in a or not a else a)
        return " ".join(shown)

    @staticmethod
    def sleep(seconds: float) -> None:
        """잠시 기다린다."""
        time.sleep(seconds)

    # ---------- 실습 서버 ----------

    @contextmanager
    def background(self, label: str, args: list[str], *, cwd: Path, ready: str,
                   tcp_port: int | None = None, show: str | None = None) -> Iterator[subprocess.Popen]:
        """서버를 뒤에서 띄우고 출력에 ready 문구가 나올 때까지 기다린다. 블록이 끝나면 끄고 출력을 기록한다."""
        if tcp_port is not None and self.port_open(tcp_port):
            raise TestError(f"127.0.0.1:{tcp_port} 를 이미 다른 프로그램이 쓰고 있습니다. "
                            "터미널에서 띄워 둔 실습 서버가 있다면 끄고 다시 실행하세요.")
        env = {**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1", "PYTHONUNBUFFERED": "1"}
        proc = self.ctx.spawn(args, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        lines: list[str] = []
        is_ready = threading.Event()

        def read_output() -> None:
            assert proc.stdout is not None
            for raw in proc.stdout:
                line = raw.decode("utf-8", errors="replace").rstrip()
                lines.append(line)
                if ready in line:
                    is_ready.set()

        reader = threading.Thread(target=read_output, daemon=True)
        reader.start()
        try:
            if not is_ready.wait(10):
                raise TestError(f"서버가 10초 안에 준비되지 않았습니다:\n" + "\n".join(lines))
            yield proc
        finally:
            time.sleep(0.3)
            self.ctx.finish(proc)
            reader.join(timeout=5)
            self.steps.append({"label": label, "command": (show or self.pretty(args)) + "   ← 뒤에서 실행한 서버",
                               "output": "\n".join(lines)})

    @contextmanager
    def lab_server(self, label: str, script: Path, *args: str, tcp_port: int | None = None) -> Iterator[subprocess.Popen]:
        """실습 폴더의 서버 스크립트를 뒤에서 띄운다. 실습 서버는 모두 시작할 때 '대기 중'을 출력한다."""
        with self.background(label, [self.ctx.python, str(script), *args], cwd=script.parent, ready="대기 중",
                             tcp_port=tcp_port, show=self.pretty(["python", script.name, *args])) as proc:
            yield proc

    @staticmethod
    def port_open(port: int) -> bool:
        """127.0.0.1:port에서 누군가 접속을 받고 있는지 확인한다."""
        with socket.socket() as s:
            s.settimeout(0.3)
            return s.connect_ex(("127.0.0.1", port)) == 0

    # ---------- 캡처 ----------

    @contextmanager
    def capture(self, name: str, interface: str, capture_filter: str, seconds: float) -> Iterator[Path]:
        """dumpcap으로 seconds초 동안 캡처한다. 블록 안에서 통신을 일으키고, 블록이 끝나면 캡처가 끝날 때까지 기다린다."""
        path = self.ctx.workdir / f"{name}.pcapng"
        path.unlink(missing_ok=True)
        args = [str(self.ctx.dumpcap), "-i", interface, "-f", capture_filter, "-a", f"duration:{seconds}", "-q", "-w", str(path)]
        proc = self.ctx.spawn(args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=self.ctx.wireshark_env())
        ready = threading.Event()
        lines: list[str] = []

        def read_stderr() -> None:
            assert proc.stderr is not None
            for raw in proc.stderr:
                line = raw.decode("utf-8", errors="replace").rstrip()
                lines.append(line)
                if line.startswith("Capturing on"):
                    ready.set()

        threading.Thread(target=read_stderr, daemon=True).start()
        if not ready.wait(15):
            stopped = self.ctx.finish(proc)
            raise TestError("캡처(dumpcap)가 15초 안에 시작되지 않았습니다. 보안 프로그램 알림 창이 떠 있는지 확인하세요.\n"
                            + ("" if stopped else f"dumpcap(PID {proc.pid})이 종료되지 않았습니다. 알림 창에 응답하거나 PC를 재시작하면 정리됩니다.\n")
                            + "\n".join(lines))
        started = time.time()
        try:
            yield path
        finally:
            remaining = seconds - (time.time() - started)
            try:
                proc.wait(timeout=max(remaining, 0) + 15)  # 정해진 시간이 지나면 dumpcap이 스스로 끝난다
            except subprocess.TimeoutExpired:
                pass
            self.ctx.finish(proc)  # 이미 끝났으면 아무 일도 하지 않고, 남아 있으면 자식까지 끝낸다
        self.steps.append({
            "label": "패킷 캡처",
            "command": f'dumpcap -i "{interface}" -f "{capture_filter}" -a duration:{seconds}',
            "output": "\n".join(lines),
        })

    def fields(self, path: Path, display_filter: str, names: list[str], options: list[str] | None = None) -> list[list[str]]:
        """캡처 파일에서 display_filter에 맞는 패킷의 필드 값을 행 목록으로 읽는다."""
        args = [str(self.ctx.tshark), "-r", str(path), "-Y", display_filter, "-T", "fields", "-E", "separator=\t"]
        for opt in options or []:
            args += ["-o", opt]
        for n in names:
            args += ["-e", n]
        proc = subprocess.run(args, capture_output=True, timeout=60, env=self.ctx.wireshark_env())
        if proc.returncode != 0:
            raise TestError("tshark 읽기 실패: " + proc.stderr.decode("utf-8", errors="replace"))
        text = proc.stdout.decode("utf-8", errors="replace")
        return [line.split("\t") for line in text.splitlines() if line.strip()]

    def count(self, path: Path, display_filter: str, options: list[str] | None = None) -> int:
        """display_filter에 맞는 패킷 수를 센다."""
        return len(self.fields(path, display_filter, ["frame.number"], options))

    def packet_hex(self, path: Path, display_filter: str) -> str:
        """조건에 맞는 첫 패킷의 원본 바이트를 Hex Stream 문자열로 반환한다."""
        proc = subprocess.run([str(self.ctx.tshark), "-r", str(path), "-Y", display_filter, "-T", "json", "-x"],
                              capture_output=True, timeout=60, env=self.ctx.wireshark_env())
        packets = json.loads(proc.stdout.decode("utf-8", errors="replace") or "[]")
        if not packets:
            raise TestError(f"'{display_filter}' 에 맞는 패킷이 캡처되지 않았습니다")
        return packets[0]["_source"]["layers"]["frame_raw"][0]

    def table(self, title: str, path: Path, display_filter: str, columns: list[tuple[str, str]],
              options: list[str] | None = None, limit: int = 60) -> list[list[str]]:
        """캡처 파일에서 표 하나를 만들어 결과에 붙이고, 읽은 행을 반환한다."""
        rows = self.fields(path, display_filter, [c[1] for c in columns], options)
        self.tables.append({
            "title": title,
            "filter": display_filter,
            "columns": [c[0] for c in columns],
            "rows": rows[:limit],
            "truncated": max(len(rows) - limit, 0),
        })
        return rows

    def packets(self, title: str, path: Path, display_filter: str, options: list[str] | None = None,
                limit: int = 60) -> list[list[str]]:
        """Wireshark 기본 목록과 같은 열(번호, 시간, 출발, 도착, 프로토콜, 요약)로 표를 만든다."""
        return self.table(title, path, display_filter, [
            ("No.", "frame.number"), ("Time", "frame.time_relative"), ("Source", "_ws.col.def_src"),
            ("Destination", "_ws.col.def_dst"), ("Protocol", "_ws.col.protocol"), ("Info", "_ws.col.info"),
        ], options, limit)

    # ---------- 확인 ----------

    def check(self, label: str, passed: bool, detail: str = "", warn_only: bool = False) -> bool:
        """확인 결과 하나를 기록한다. warn_only면 실패해도 '주의'로 표시한다(네트워크 환경 탓일 수 있는 것)."""
        status = "pass" if passed else ("warn" if warn_only else "fail")
        self.checks.append({"label": label, "status": status, "detail": detail})
        return passed
