"""챕터(00~09)별 설명과 자동 테스트 정의. 각 테스트는 실습 스크립트를 실제로 실행하고 dumpcap으로 캡처해 tshark로 확인한다."""

import ipaddress
import re
import socket
from dataclasses import dataclass
from typing import Callable

from runner import LOOPBACK_IF, Ctx, Run, TestError


@dataclass
class Test:
    """화면의 테스트 버튼 하나."""

    id: str
    title: str
    description: str
    look: list[str]  # 결과에서 눈여겨볼 점
    func: Callable[[Ctx, Run], None]
    seconds: int  # 대략 걸리는 시간(화면 안내용)


@dataclass
class Chapter:
    """화면의 챕터 하나."""

    id: str
    folder: str
    title: str
    goal: str
    learn: list[str]
    manual: list[str]  # 자동으로 못 하는, 직접 해 볼 것
    tests: list[Test]


TCP_COLUMNS = [
    ("No.", "frame.number"), ("Time", "frame.time_relative"), ("출발 포트", "tcp.srcport"), ("도착 포트", "tcp.dstport"),
    ("Flags", "tcp.flags.str"), ("Seq", "tcp.seq"), ("Ack", "tcp.ack"), ("Len", "tcp.len"), ("Win", "tcp.window_size"),
]


def lab(ctx: Ctx, folder: str, name: str):
    """실습 폴더 안 파일 경로를 반환한다."""
    return ctx.repo / folder / name


def curl(*args: str) -> list[str]:
    """Windows 기본 curl 명령을 만든다."""
    return ["curl.exe", *args]


# ───────────────────────── 00 준비 ─────────────────────────

def t00_env(ctx: Ctx, run: Run) -> None:
    out = run.cmd("캡처 가능한 어댑터 목록", [str(ctx.dumpcap), "-D"])
    run.check("Npcap이 동작한다", "\\Device\\NPF_" in out, "dumpcap -D에 \\Device\\NPF_... 어댑터가 나오면 Npcap이 패킷을 잡을 수 있는 상태")
    run.check("loopback 어댑터가 있다", "Adapter for loopback traffic capture" in out, "01·02·04·08 실습용")
    net = ctx.network()
    run.note("인터넷 어댑터", f"이름: {net.alias}\n내 IP: {net.local_ip}/{net.prefix}\n게이트웨이: {net.gateway}")
    run.check(f"인터넷 어댑터 '{net.alias}'가 목록에 있다", f"({net.alias})" in out, "03·05·06·07 실습용")


def t00_first(ctx: Ctx, run: Run) -> None:
    server = [ctx.python, "-m", "http.server", "8080", "--bind", "127.0.0.1"]
    with run.background("Python 내장 웹 서버", server, cwd=ctx.workdir, ready="Serving HTTP", tcp_port=8080,
                        show="python -m http.server 8080 --bind 127.0.0.1"):
        with run.capture("t00", LOOPBACK_IF, "tcp port 8080", 4) as pcap:
            run.sleep(0.5)
            run.cmd("요청 보내기", curl("-s", "-o", "NUL", "-w", "HTTP 상태 코드: %{http_code}\\n", "http://127.0.0.1:8080/"))
    run.packets("캡처된 패킷 (tcp.port == 8080)", pcap, "tcp.port == 8080")
    run.check("SYN이 잡혔다", run.count(pcap, "tcp.flags.syn == 1 && tcp.flags.ack == 0") >= 1)
    run.check("HTTP 요청이 잡혔다", run.count(pcap, "http.request") >= 1)
    run.check("HTTP 200 응답이 잡혔다", run.count(pcap, "http.response.code == 200") >= 1)


# ───────────────────────── 01 TCP ─────────────────────────

def t01_tcp(ctx: Ctx, run: Run) -> None:
    folder = "01-tcp-connection"
    with run.lab_server("01 TCP 에코 서버", lab(ctx, folder, "server.py"), tcp_port=9000):
        with run.capture("t01", LOOPBACK_IF, "tcp port 9000", 4) as pcap:
            run.sleep(0.5)
            run.py("클라이언트: hello tcp 보내기", lab(ctx, folder, "client.py"), "--message", "hello tcp")
    rows = run.table("TCP 패킷 (상대 Seq/Ack)", pcap, "tcp.port == 9000", TCP_COLUMNS)
    flags = [r[4] for r in rows]
    run.check("1~3번이 SYN → SYN,ACK → ACK (3-way handshake)",
              len(flags) >= 3 and flags[0].endswith("S·") and "A" in flags[1] and "S" in flags[1] and flags[2].replace("·", "") == "A",
              " / ".join(flags[:3]))
    data = [r for r in rows if r[7] == "9"]
    run.check("9바이트 데이터가 양쪽으로 한 번씩 갔다", len(data) == 2, f"Len=9 패킷 {len(data)}개")
    fins = run.count(pcap, "tcp.port == 9000 && tcp.flags.fin == 1")
    run.check("양쪽이 FIN을 보냈다", fins == 2, f"FIN 패킷 {fins}개")
    acks = [r for r in rows if r[2] == "9000" and r[6] == "10"]
    run.check("서버의 Ack가 9만큼 늘어 10이 됐다", len(acks) >= 1, "받은 바이트 수만큼 Ack가 증가")


# ───────────────────────── 02 HTTP ─────────────────────────

def t02_raw(ctx: Ctx, run: Run) -> None:
    folder = "02-http-raw"
    with run.lab_server("02 HTTP 서버 (받은 원본 바이트 출력)", lab(ctx, folder, "server.py"), tcp_port=8000):
        with run.capture("t02a", LOOPBACK_IF, "tcp port 8000", 5) as pcap:
            run.sleep(0.5)
            run.py("손으로 쓴 request.txt 그대로 보내기", lab(ctx, folder, "send_raw.py"))
            run.cmd("curl -v로 같은 요청 보내기", curl("-v", "http://127.0.0.1:8000/"))
    run.packets("캡처된 HTTP (http)", pcap, "http")
    run.check("요청 2개가 HTTP로 해석됐다", run.count(pcap, "http.request") == 2)
    run.check("응답 2개 모두 200 OK", run.count(pcap, "http.response.code == 200") == 2)
    syns = run.count(pcap, "tcp.flags.syn == 1 && tcp.flags.ack == 0")
    run.check("요청마다 새 TCP 연결(Connection: close)", syns == 2, f"SYN {syns}개")


def t02_status(ctx: Ctx, run: Run) -> None:
    folder = "02-http-raw"
    bad = ctx.workdir / "bad-request.txt"
    bad.write_text("HELLO\n\n", encoding="utf-8")
    url = "http://127.0.0.1:8000"
    fmt = "→ %{http_code}\\n"
    with run.lab_server("02 HTTP 서버", lab(ctx, folder, "server.py"), tcp_port=8000):
        with run.capture("t02b", LOOPBACK_IF, "tcp port 8000", 6) as pcap:
            run.sleep(0.5)
            codes = {
                "GET /": run.cmd("GET /", curl("-s", "-o", "NUL", "-w", fmt, f"{url}/")),
                "POST /echo": run.cmd("POST /echo (본문을 그대로 돌려받기)", curl("-s", "-d", "hello body", f"{url}/echo")),
                "GET /nope": run.cmd("없는 경로", curl("-s", "-o", "NUL", "-w", fmt, f"{url}/nope")),
                "POST /": run.cmd("경로는 있는데 메서드가 틀림", curl("-s", "-o", "NUL", "-w", fmt, "-X", "POST", f"{url}/")),
            }
            raw = run.py("형식이 틀린 요청 (요청 줄이 'HELLO')", lab(ctx, folder, "send_raw.py"), str(bad))
    run.table("캡처된 HTTP 응답 상태 줄", pcap, "http.response", [
        ("No.", "frame.number"), ("상태 코드", "http.response.code"), ("설명", "http.response.phrase"), ("Content-Length", "http.content_length_header"),
    ])
    run.check("GET / → 200", "200" in codes["GET /"])
    run.check("POST /echo → 받은 본문을 그대로 돌려줌", codes["POST /echo"].strip() == "hello body")
    run.check("없는 경로 → 404", "404" in codes["GET /nope"])
    run.check("틀린 메서드 → 405", "405" in codes["POST /"])
    run.check("형식이 틀린 요청 → 400", "400 Bad Request" in raw)


# ───────────────────────── 03 DNS ─────────────────────────

def t03_dns(ctx: Ctx, run: Run) -> None:
    iface = ctx.internet_interface()
    with run.capture("t03", iface, "udp port 53 or tcp port 80", 8) as pcap:
        run.sleep(0.5)
        run.cmd("DNS에 example.com 주소 묻기", ["nslookup", "example.com"], console=True)
        out = run.cmd("HTTP로 example.com 요청", curl("-s", "-o", "NUL", "-w", "연결한 주소: %{remote_ip}\\n상태 코드: %{http_code}\\n", "http://example.com/"))
    m = re.search(r"연결한 주소: (\S+)", out)
    ip = m.group(1) if m else ""
    run.table("DNS 질의와 응답", pcap, 'dns.qry.name == "example.com"', [
        ("No.", "frame.number"), ("Time", "frame.time_relative"), ("응답?", "dns.flags.response"), ("질의 종류", "dns.qry.type"),
        ("Transaction ID", "dns.id"), ("받은 IPv4", "dns.a"), ("받은 IPv6", "dns.aaaa"),
    ])
    run.packets(f"그다음 TCP 연결과 HTTP (ip.addr == {ip})", pcap, f"tcp.port == 80 && ip.addr == {ip}" if ip else "tcp.port == 80")
    run.check("DNS 질의(A)가 나갔다", run.count(pcap, 'dns.qry.name == "example.com" && dns.flags.response == 0 && dns.qry.type == 1') >= 1)
    run.check("DNS 응답에 IPv4 주소가 들어 있다", run.count(pcap, 'dns.qry.name == "example.com" && dns.a') >= 1)
    run.check("curl이 연결한 주소로 SYN이 나갔다", bool(ip) and run.count(pcap, f"ip.dst == {ip} && tcp.flags.syn == 1 && tcp.flags.ack == 0") >= 1, ip)
    run.check("HTTP GET 요청이 평문으로 보인다", run.count(pcap, 'http.request && http.host == "example.com"') >= 1)


# ───────────────────────── 04 keep-alive · 쿠키 ─────────────────────────

def t04_keepalive(ctx: Ctx, run: Run) -> None:
    folder = "04-keepalive-cookie-session"
    url = "http://127.0.0.1:8001"
    fmt = "%{url} ← 내 포트 %{local_port}\\n"
    with run.lab_server("04 서버", lab(ctx, folder, "server.py"), tcp_port=8001):
        with run.capture("t04a", LOOPBACK_IF, "tcp port 8001", 6) as pcap:
            run.sleep(0.5)
            keep = run.cmd("keep-alive: URL 두 개를 한 번에", curl("-s", "-o", "NUL", "-o", "NUL", "-w", fmt, f"{url}/", f"{url}/me"))
            run.sleep(1)
            close = run.cmd("Connection: close를 붙여서", curl("-s", "-o", "NUL", "-o", "NUL", "-w", fmt, "-H", "Connection: close", f"{url}/", f"{url}/me"))
    run.table("새 연결 시작(SYN)과 HTTP 요청", pcap, "(tcp.flags.syn == 1 && tcp.flags.ack == 0) || http.request", [
        ("No.", "frame.number"), ("Time", "frame.time_relative"), ("내 포트", "tcp.srcport"), ("요약", "_ws.col.info"),
    ])
    keep_ports = re.findall(r"내 포트 (\d+)", keep)
    close_ports = re.findall(r"내 포트 (\d+)", close)
    run.check("keep-alive: 두 요청이 같은 포트(같은 연결)", len(keep_ports) == 2 and keep_ports[0] == keep_ports[1], ", ".join(keep_ports))
    run.check("close: 두 요청이 다른 포트(연결 2개)", len(close_ports) == 2 and close_ports[0] != close_ports[1], ", ".join(close_ports))
    syns = run.count(pcap, "tcp.flags.syn == 1 && tcp.flags.ack == 0")
    run.check("SYN이 모두 3번 (keep-alive 1 + close 2)", syns == 3, f"SYN {syns}개")


def t04_cookie(ctx: Ctx, run: Run) -> None:
    folder = "04-keepalive-cookie-session"
    url = "http://127.0.0.1:8001"
    jar = ctx.workdir / "cookies.txt"
    jar.unlink(missing_ok=True)
    with run.lab_server("04 서버", lab(ctx, folder, "server.py"), tcp_port=8001):
        with run.capture("t04b", LOOPBACK_IF, "tcp port 8001", 6) as pcap:
            run.sleep(0.5)
            first = run.cmd("1. 쿠키 없이 /me", curl("-s", "-w", "\\n→ %{http_code}", f"{url}/me"))
            login = run.cmd("2. 로그인 (Set-Cookie 받기)", curl("-v", "-c", str(jar), "-d", "name=kim", f"{url}/login"),
                            show='curl.exe -v -c cookies.txt -d "name=kim" http://127.0.0.1:8001/login')
            me = run.cmd("3. 쿠키를 붙여 /me", curl("-v", "-b", str(jar), f"{url}/me"),
                         show="curl.exe -v -b cookies.txt http://127.0.0.1:8001/me")
            fake = run.cmd("4. 지어낸 sid로 /me", curl("-s", "-w", "\\n→ %{http_code}", "-H", "Cookie: sid=deadbeef", f"{url}/me"))
    run.table("쿠키가 오간 패킷", pcap, "http.set_cookie || http.cookie || http.response.code == 401", [
        ("No.", "frame.number"), ("요청", "http.request.uri"), ("상태", "http.response.code"),
        ("Set-Cookie (서버→)", "http.set_cookie"), ("Cookie (→서버)", "http.cookie"),
    ])
    sid = re.search(r"Set-Cookie: sid=([0-9a-f]+)", login)
    run.check("쿠키 없이 /me → 401", "401" in first)
    run.check("로그인 응답에 Set-Cookie: sid=... 가 있다", sid is not None, sid.group(0) if sid else "")
    run.check("다음 요청에 같은 sid가 Cookie로 실려 갔다", bool(sid) and f"Cookie: sid={sid.group(1)}" in me)
    run.check("쿠키를 붙인 /me → 200, 이름을 알아봄", "kim님" in me)
    run.check("지어낸 sid → 401", "401" in fake)
    run.check("sid 값이 캡처에 평문으로 보인다 (HTTPS가 아니므로)", run.count(pcap, "http.cookie") >= 1)


# ───────────────────────── 05 HTTPS ─────────────────────────

def t05_https(ctx: Ctx, run: Run) -> None:
    keylog = ctx.workdir / "sslkeys.txt"
    keylog.unlink(missing_ok=True)
    iface = ctx.internet_interface()
    with run.capture("t05", iface, "tcp port 443", 8) as pcap:
        run.sleep(0.5)
        run.py("HTTPS 요청 + TLS 키 기록", lab(ctx, "05-https-tls", "client.py"), "--keylog", str(keylog))
    hello = run.fields(pcap, 'tls.handshake.type == 1 && tls.handshake.extensions_server_name == "example.com"', ["tcp.stream"])
    if not hello:
        raise TestError("example.com으로 가는 Client Hello가 캡처되지 않았습니다")
    stream = hello[0][0]
    flt = f"tcp.stream == {stream}"
    with_key = [f"tls.keylog_file:{keylog}"]
    run.table("① 키 없이: TLS 레코드만 보인다", pcap, flt, [
        ("No.", "frame.number"), ("Time", "frame.time_relative"), ("Protocol", "_ws.col.protocol"),
        ("SNI(평문)", "tls.handshake.extensions_server_name"), ("Info", "_ws.col.info"),
    ], limit=25)
    run.table("② 키를 넣고: 같은 패킷 안의 HTTP가 풀린다", pcap, f"{flt} && http", [
        ("No.", "frame.number"), ("요청", "http.request.line"), ("응답", "http.response.line"),
        ("User-Agent", "http.user_agent"), ("상태", "http.response.code"),
    ], options=with_key)
    run.note("TLS 키 파일 (앞 단어만)", "\n".join(line.split(" ")[0] for line in keylog.read_text().splitlines() if line))
    run.check("Client Hello의 SNI에 example.com이 평문으로 보인다", True, "접속하는 사이트 이름은 HTTPS로도 가려지지 않음")
    no_key = run.count(pcap, f"{flt} && http")
    run.check("키 없이는 HTTP가 0건", no_key == 0, f"{no_key}건")
    decrypted = run.count(pcap, f"{flt} && http.request", with_key)
    run.check("키를 넣으면 GET 요청이 보인다", decrypted >= 1, f"{decrypted}건")
    run.check("키를 넣으면 200 응답이 보인다", run.count(pcap, f"{flt} && http.response.code == 200", with_key) >= 1)


# ───────────────────────── 06 링크 계층 ─────────────────────────

def mac_norm(text: str) -> str:
    """aa-bb-.. 이나 aa:bb:.. 형식의 MAC을 소문자 콜론 형식으로 맞춘다."""
    return text.strip().lower().replace("-", ":")


def arp_table(run: Run, label: str) -> tuple[str, dict[str, str]]:
    """arp -a를 실행해 (원문, IP → MAC 사전)을 반환한다."""
    out = run.cmd(label, ["arp", "-a"], console=True)
    entries = dict(re.findall(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})", out))
    return out, {ip: mac_norm(m) for ip, m in entries.items()}


def t06_mac(ctx: Ctx, run: Run) -> None:
    net = ctx.network()
    with run.capture("t06a", net.alias, "tcp port 80", 6) as pcap:
        run.sleep(0.5)
        out = run.cmd("example.com에 HTTP 요청", curl("-s", "-o", "NUL", "-w", "연결한 주소: %{remote_ip}\\n", "http://example.com/"))
    _, table = arp_table(run, "ARP 캐시 (IP → MAC 표)")
    gw_mac = table.get(net.gateway, "")
    run.note("내 네트워크", f"내 IP: {net.local_ip}/{net.prefix}\n게이트웨이: {net.gateway}\n게이트웨이 MAC (arp -a): {gw_mac or '표에 없음'}")
    m = re.search(r"연결한 주소: (\S+)", out)
    ip = m.group(1) if m else ""
    rows = run.table("한 패킷 안의 두 주소: MAC(바로 다음 칸) vs IP(최종 목적지)", pcap, f"ip.dst == {ip}", [
        ("No.", "frame.number"), ("출발 MAC", "eth.src"), ("도착 MAC", "eth.dst"), ("출발 IP", "ip.src"), ("도착 IP", "ip.dst"), ("Info", "_ws.col.info"),
    ], limit=8)
    run.check("게이트웨이 MAC을 ARP 캐시에서 찾았다", bool(gw_mac), f"{net.gateway} → {gw_mac}")
    run.check("도착 IP는 example.com", bool(rows) and rows[0][4] == ip, ip)
    run.check("도착 MAC은 example.com이 아니라 게이트웨이", bool(rows) and bool(gw_mac) and mac_norm(rows[0][2]) == gw_mac,
              f"도착 MAC {rows[0][2] if rows else '-'} / 게이트웨이 MAC {gw_mac}")


def t06_arp(ctx: Ctx, run: Run) -> None:
    net = ctx.network()
    _, table = arp_table(run, "ARP 캐시 확인 (안 쓰는 주소 고르기)")
    subnet = ipaddress.ip_network(f"{net.local_ip}/{net.prefix}", strict=False)
    taken = set(table) | {net.local_ip, net.gateway}
    hosts = list(subnet.hosts())
    target = next((str(h) for h in reversed(hosts[-60:]) if str(h) not in taken), None)
    if target is None:
        raise TestError("ARP 캐시에 없는 주소를 찾지 못했습니다")
    run.note("고른 주소", f"{target} (같은 네트워크 {subnet} 안에서 ARP 캐시에 없는 주소)")
    with run.capture("t06b", net.alias, "arp", 7) as pcap:
        run.sleep(0.5)
        run.cmd(f"{target}에 ping (MAC을 몰라서 ARP부터 나감)", ["ping", "-n", "1", "-w", "1000", target], console=True)
        run.sleep(2.5)
    mine = run.table("내 PC가 보낸 ARP 요청", pcap, f"arp.dst.proto_ipv4 == {target}", [
        ("Time", "frame.time_relative"), ("Ethernet 도착", "eth.dst"), ("동작", "arp.opcode"),
        ("보낸 쪽 IP", "arp.src.proto_ipv4"), ("찾는 IP", "arp.dst.proto_ipv4"), ("찾는 MAC", "arp.dst.hw_mac"), ("Info", "_ws.col.info"),
    ])
    others = run.count(pcap, f"arp && !(arp.dst.proto_ipv4 == {target})")
    run.check("ARP 요청 'Who has ...?'가 나갔다", len(mine) >= 1, f"{len(mine)}번")
    run.check("브로드캐스트로 보냈다 (ff:ff:ff:ff:ff:ff)", bool(mine) and mine[0][1] == "ff:ff:ff:ff:ff:ff")
    run.check("찾는 MAC은 아직 모르므로 0", bool(mine) and mine[0][5] == "00:00:00:00:00:00")
    run.check("같은 시간 동안 다른 기기의 ARP도 보였다", others > 0, f"{others}개", warn_only=True)


# ───────────────────────── 07 IP · ICMP ─────────────────────────

ICMP_COLUMNS = [
    ("No.", "frame.number"), ("Time", "frame.time_relative"), ("출발", "ip.src"), ("도착", "ip.dst"),
    ("TTL", "ip.ttl"), ("ICMP 타입", "icmp.type"), ("Info", "_ws.col.info"),
]


def t07_ttl(ctx: Ctx, run: Run) -> None:
    iface = ctx.internet_interface()
    target = socket.gethostbyname("example.com")
    with run.capture("t07a", iface, f"icmp", 12) as pcap:
        run.sleep(0.5)
        run.cmd("ping 2번", ["ping", "-n", "2", target], console=True)
        run.cmd("TTL=1로 ping", ["ping", "-n", "1", "-i", "1", "-w", "1000", target], console=True)
        run.cmd("TTL=2로 ping", ["ping", "-n", "1", "-i", "2", "-w", "1000", target], console=True)
    run.table("ICMP 패킷 (TTL과 타입)", pcap, "icmp", ICMP_COLUMNS)
    replies = run.fields(pcap, f"icmp.type == 0 && ip.src == {target}", ["ip.ttl"])
    sent = run.fields(pcap, f"icmp.type == 8 && ip.dst == {target} && !(icmp.type == 11)", ["ip.ttl"])
    exceeded = run.fields(pcap, "icmp.type == 11", ["ip.src"])
    run.check("Echo 요청·응답이 오갔다", bool(replies), f"응답 {len(replies)}개")
    if replies:
        ttl = int(replies[0][0])
        run.check(f"응답 TTL {ttl}: 64에서 시작했다면 약 {64 - ttl}개 라우터를 지남", True)
    run.check("내 요청 TTL이 128, 1, 2로 나갔다", {"128", "1", "2"} <= {r[0] for r in sent}, ", ".join(r[0] for r in sent))
    run.check("어떤 라우터가 TTL 초과(타입 11)로 답했다", bool(exceeded),
              ", ".join(sorted({r[0].split(",")[0] for r in exceeded})) or "이 네트워크가 막고 있음", warn_only=True)


def t07_tracert(ctx: Ctx, run: Run) -> None:
    iface = ctx.internet_interface()
    target = socket.gethostbyname("example.com")
    with run.capture("t07b", iface, "icmp", 16) as pcap:
        run.sleep(0.5)
        run.cmd("tracert (4단계까지)", ["tracert", "-d", "-h", "4", "-w", "500", target], console=True, timeout=40)
    run.table("tracert가 보낸 요청(TTL이 1씩 늘어남)과 라우터의 답", pcap, f"(icmp.type == 8 && ip.dst == {target}) || icmp.type == 11", ICMP_COLUMNS)
    # TTL 초과 응답 안에도 원래 요청(타입 8)이 들어 있으므로 그 패킷은 빼고 센다
    ttls = [r[0] for r in run.fields(pcap, f"icmp.type == 8 && ip.dst == {target} && !(icmp.type == 11)", ["ip.ttl"])]
    run.check("TTL 1, 2, 3, 4로 3번씩 보냈다", ttls[:12] == [t for t in "1234" for _ in range(3)], " ".join(ttls))
    run.check("TTL 초과 응답을 받은 단계가 있다", run.count(pcap, "icmp.type == 11") > 0, warn_only=True)


def t07_frag(ctx: Ctx, run: Run) -> None:
    iface = ctx.internet_interface()
    target = socket.gethostbyname("example.com")
    with run.capture("t07c", iface, f"host {target}", 6) as pcap:
        run.sleep(0.5)
        run.cmd("3000바이트 ping", ["ping", "-n", "1", "-l", "3000", target], console=True)
    rows = run.table("IP 조각들 (조각 위치는 헤더에 8바이트 단위로 적힘: 185 × 8 = 1480바이트)", pcap, "ip", [
        ("No.", "frame.number"), ("출발", "ip.src"), ("IP ID", "ip.id"), ("MF", "ip.flags.mf"),
        ("조각 위치(8바이트 단위)", "ip.frag_offset"), ("IP 길이", "ip.len"), ("Info", "_ws.col.info"),
    ])
    out = [r for r in rows if r[1] != target]
    offsets = [str(int(r[4]) * 8) for r in out]
    run.check("내 요청이 3조각으로 나갔다", len(out) == 3, f"{len(out)}조각")
    run.check("세 조각의 IP ID가 같다", len({r[2] for r in out}) == 1, ", ".join(r[2] for r in out))
    run.check("조각 위치가 0, 1480, 2960바이트", offsets == ["0", "1480", "2960"], ", ".join(offsets))
    run.check("마지막 조각만 MF=False", [r[3] for r in out] == ["True", "True", "False"], ", ".join(r[3] for r in out))
    run.check("응답도 조각으로 돌아왔다", len(rows) - len(out) >= 2, f"{len(rows) - len(out)}조각", warn_only=True)


# ───────────────────────── 08 TCP 심화 ─────────────────────────

def t08_rst(ctx: Ctx, run: Run) -> None:
    with run.capture("t08a", LOOPBACK_IF, "tcp port 9", 5) as pcap:
        run.sleep(0.5)
        out = run.py("닫힌 포트 9에 접속", lab(ctx, "08-tcp-deep", "connect_probe.py"), "--port", "9")
    run.table("SYN과 RST", pcap, "tcp.port == 9", TCP_COLUMNS)
    rsts = run.count(pcap, "tcp.flags.reset == 1")
    run.check("연결 거부(RST)", "연결 거부" in out)
    run.check("상대가 RST로 답했다", rsts >= 1, f"RST {rsts}개")
    run.check("Windows는 RST를 받고도 SYN을 더 보낸다", rsts > 1, f"SYN/RST {rsts}쌍", warn_only=True)


def t08_syn(ctx: Ctx, run: Run) -> None:
    iface = ctx.internet_interface()
    with run.capture("t08b", iface, "host 10.255.255.1", 12) as pcap:
        run.sleep(0.5)
        out = run.py("응답 없는 주소에 접속", lab(ctx, "08-tcp-deep", "connect_probe.py"),
                     "--host", "10.255.255.1", "--port", "80", "--timeout", "9", timeout=30)
    rows = run.table("같은 SYN이 다시 나간다", pcap, "ip.addr == 10.255.255.1", [
        ("No.", "frame.number"), ("Time", "frame.time_relative"), ("이전 패킷과의 간격(초)", "frame.time_delta_displayed"), ("Info", "_ws.col.info"),
    ])
    gaps = [round(float(r[2])) for r in rows[1:]]
    run.check("시간 초과로 끝났다", "시간 초과" in out)
    run.check("SYN을 2번 이상 재전송했다", run.count(pcap, "tcp.analysis.retransmission") >= 2)
    run.check("재전송 간격이 두 배씩 늘었다", len(gaps) >= 2 and all(b >= a * 1.5 for a, b in zip(gaps, gaps[1:])), f"간격 {gaps}초")


def t08_flow(ctx: Ctx, run: Run) -> None:
    folder = "08-tcp-deep"
    with run.lab_server("흐름 제어 서버 (5초 동안 읽지 않음)", lab(ctx, folder, "flow_server.py"), tcp_port=9100):
        with run.capture("t08c", LOOPBACK_IF, "tcp port 9100", 10) as pcap:
            run.sleep(0.5)
            run.py("계속 보내는 클라이언트", lab(ctx, folder, "flow_client.py"), timeout=30)
            run.sleep(1)
    events = "tcp.analysis.window_full || tcp.analysis.zero_window || tcp.analysis.zero_window_probe || tcp.analysis.window_update"
    run.table("처음 20개 패킷: 서버 Win이 줄어든다", pcap, "tcp.port == 9100 && frame.number <= 20", TCP_COLUMNS)
    run.table("흐름 제어 사건들", pcap, events, [("No.", "frame.number"), ("Time", "frame.time_relative"), ("Win", "tcp.window_size"), ("Info", "_ws.col.info")])
    run.check("[TCP Window Full]", run.count(pcap, "tcp.analysis.window_full") >= 1)
    run.check("[TCP ZeroWindow] 서버가 Win=0을 알림", run.count(pcap, "tcp.analysis.zero_window") >= 1)
    run.check("[TCP ZeroWindowProbe] 클라이언트가 열렸는지 떠봄", run.count(pcap, "tcp.analysis.zero_window_probe") >= 1)
    run.check("[TCP Window Update] 서버가 읽기 시작하자 다시 열림", run.count(pcap, "tcp.analysis.window_update") >= 1)


def t08_udp(ctx: Ctx, run: Run) -> None:
    script = lab(ctx, "08-tcp-deep", "udp_echo.py")
    with run.lab_server("UDP 에코 서버", script, "server"):
        with run.capture("t08d", LOOPBACK_IF, "udp port 9300 or tcp port 9300", 4) as pcap:
            run.sleep(0.5)
            run.py("UDP 클라이언트", script, "client")
    run.table("UDP 패킷 전부", pcap, "udp", [
        ("No.", "frame.number"), ("Time", "frame.time_relative"), ("출발 포트", "udp.srcport"), ("도착 포트", "udp.dstport"),
        ("UDP 길이", "udp.length"), ("데이터", "data.text"),
    ], options=["data.show_as_text:TRUE"])
    total = run.count(pcap, "frame")
    run.check("패킷이 딱 2개 (보내기, 돌려받기)", total == 2, f"{total}개")
    run.check("TCP 패킷(handshake, ACK, FIN)이 하나도 없다", run.count(pcap, "tcp") == 0)


# ───────────────────────── 09 캡슐화 해부 ─────────────────────────

def t09_http(ctx: Ctx, run: Run) -> None:
    iface = ctx.internet_interface()
    with run.capture("t09a", iface, "tcp port 80", 6) as pcap:
        run.sleep(0.5)
        run.cmd("example.com에 HTTP 요청", curl("-s", "-o", "NUL", "http://example.com/"))
    hex_stream = run.packet_hex(pcap, "http.request")
    run.note("Hex Stream (Wireshark: Copy → as Hex Stream 과 같은 값)", hex_stream)
    out = run.py("dissect.py로 해부", lab(ctx, "09-encapsulation", "dissect.py"), hex_stream)
    rows = run.table("같은 패킷을 tshark가 해석한 값 (비교용)", pcap, "http.request", [
        ("도착 MAC", "eth.dst"), ("출발 MAC", "eth.src"), ("IP ID", "ip.id"), ("TTL", "ip.ttl"),
        ("출발 포트", "tcp.srcport"), ("Seq(raw)", "tcp.seq_raw"), ("Ack(raw)", "tcp.ack_raw"), ("Win", "tcp.window_size_value"), ("데이터 길이", "tcp.len"),
    ], limit=1)
    r = rows[0]
    for name, value in [("도착 MAC", r[0]), ("출발 MAC", r[1]), ("TTL", f"TTL                    {r[3]}"), ("출발 포트", r[4]), ("Seq", r[5]), ("Ack", r[6])]:
        run.check(f"{name}가 tshark와 같다", value.split()[-1] in out, value.split()[-1])
    run.check(f"데이터 {r[8]}바이트에 HTTP 요청 줄이 있다", f"데이터 ({r[8]}바이트)" in out and "GET / HTTP/1.1" in out)


def t09_udp(ctx: Ctx, run: Run) -> None:
    script = lab(ctx, "08-tcp-deep", "udp_echo.py")
    with run.lab_server("UDP 에코 서버", script, "server"):
        with run.capture("t09b", LOOPBACK_IF, "udp port 9300", 4) as pcap:
            run.sleep(0.5)
            run.py("UDP 클라이언트", script, "client")
    hex_stream = run.packet_hex(pcap, "udp.dstport == 9300")
    run.note("Hex Stream", hex_stream)
    out = run.py("dissect.py --link null 로 해부", lab(ctx, "09-encapsulation", "dissect.py"), "--link", "null", hex_stream)
    run.check("링크 헤더가 4바이트(Null)", "Null/Loopback (4바이트" in out)
    run.check("IP 체크섬을 직접 계산해서 일치", "직접 계산해 보니 일치" in out)
    run.check("UDP 헤더 8바이트, 데이터 hello udp", "UDP (8바이트" in out and "hello udp" in out)


# ───────────────────────── 챕터 목록 ─────────────────────────

def chapters() -> list[Chapter]:
    """화면에 보여 줄 챕터를 순서대로 반환한다."""
    return [
        Chapter("00", "00-setup", "준비: Wireshark와 Npcap", "패킷을 잡을 수 있는 상태인지 확인한다",
                ["Npcap은 패킷을 잡는 드라이버(손), Wireshark·tshark는 해석해 보여주는 화면, dumpcap은 캡처만 하는 프로그램",
                 "127.0.0.1 통신은 loopback 어댑터, 인터넷 통신은 Wi-Fi/이더넷 어댑터에서 잡힌다"],
                ["Wireshark를 열고 'Adapter for loopback traffic capture'를 더블클릭해 캡처가 시작되는지 보기"],
                [Test("t00_env", "설치 확인", "dumpcap -D로 캡처 가능한 어댑터 목록을 보고, 인터넷 어댑터를 찾는다.",
                      ["목록에 loopback 어댑터와 인터넷 어댑터가 모두 있는지"], t00_env, 3),
                 Test("t00_first", "첫 캡처", "Python 내장 웹 서버에 curl로 요청하고 loopback에서 캡처한다.",
                      ["SYN → HTTP 요청 → 200 응답 순서", "Source와 Destination이 모두 127.0.0.1"], t00_first, 6)]),
        Chapter("01", "01-tcp-connection", "TCP 연결", "HTTP 없이 TCP만으로 연결 → 데이터 → 종료를 본다",
                ["3-way handshake: SYN, SYN-ACK, ACK", "Seq는 내가 보낸 바이트 위치, Ack는 다음에 받을 위치", "FIN으로 양쪽이 각각 닫는다"],
                ["Wireshark에서 데이터 패킷을 클릭하고 아래 바이트 창에서 'hello tcp' 찾기", "Follow → TCP Stream 열어 보기"],
                [Test("t01_tcp", "에코 서버와 hello tcp", "01의 server.py와 client.py를 실행하고 캡처한다.",
                      ["Flags 열: S → SA → A → PA … → FA", "Len=9 다음 상대 Ack가 1 → 10"], t01_tcp, 6)]),
        Chapter("02", "02-http-raw", "HTTP는 TCP 위의 텍스트", "요청 줄·헤더·빈 줄·본문이 실제로 어떤 바이트인지 본다",
                ["HTTP 메시지는 \\r\\n으로 줄을 나눈 텍스트, 헤더 끝은 빈 줄(\\r\\n\\r\\n)", "상태 코드: 200, 400, 404, 405"],
                ["request.txt를 고쳐서 send_raw.py로 다시 보내 보기", "브라우저로 http://127.0.0.1:8000/ 을 열고 개발자도구 Network 탭 보기 (서버는 터미널에서 직접 실행)"],
                [Test("t02_raw", "손으로 쓴 요청 vs curl", "request.txt를 그대로 보낸 것과 curl -v 요청을 비교한다.",
                      ["서버 출력의 원본 바이트에 \\r\\n이 보인다", "curl -v의 > 줄이 서버가 받은 바이트와 같다"], t02_raw, 7),
                 Test("t02_status", "상태 코드 모음", "200 / echo / 404 / 405 / 400 을 차례로 일으킨다.",
                      ["405 응답에 Allow 헤더", "400은 서버가 파싱하다 실패한 경우"], t02_status, 8)]),
        Chapter("03", "03-dns", "DNS", "이름 → 주소 → TCP 연결 → HTTP로 이어지는 실제 인터넷 요청을 본다",
                ["DNS는 UDP 53번, 질의와 응답을 Transaction ID로 짝지음", "A는 IPv4, AAAA는 IPv6 주소를 묻는다"],
                ["관리자 PowerShell에서 ipconfig /flushdns 후 curl만 실행해 보기 (캐시를 비우면 curl도 DNS를 묻는다)"],
                [Test("t03_dns", "nslookup과 HTTP 요청", "nslookup으로 DNS를 묻고, curl로 example.com에 HTTP 요청을 보낸다.",
                      ["DNS 응답의 주소와 curl이 연결한 주소가 같다", "DNS 패킷 앞뒤에 handshake가 없다"], t03_dns, 10)]),
        Chapter("04", "04-keepalive-cookie-session", "keep-alive와 쿠키·세션", "연결 재사용과, 쿠키로 로그인 상태를 유지하는 방식을 본다",
                ["HTTP/1.1은 연결 하나로 요청 여러 개", "Set-Cookie로 받고 Cookie로 돌려보낸다", "세션 = 서버 메모리의 sid → 사용자 표"],
                ["브라우저로 http://127.0.0.1:8001/ 에서 로그인하고 개발자도구 Application → Cookies 보기 (서버는 터미널에서 직접 실행)"],
                [Test("t04_keepalive", "keep-alive vs Connection: close", "같은 두 요청을 연결 재사용 / 매번 새 연결로 보낸다.",
                      ["keep-alive는 SYN 1번, close는 SYN 2번"], t04_keepalive, 8),
                 Test("t04_cookie", "로그인과 쿠키", "/me(401) → 로그인 → /me(200) → 가짜 sid(401) 순서로 요청한다.",
                      ["Set-Cookie의 sid가 다음 요청 Cookie에 그대로 실려 감", "sid가 평문으로 캡처됨"], t04_cookie, 8)]),
        Chapter("05", "05-https-tls", "HTTPS와 TLS", "TLS가 무엇을 가리고 무엇을 남기는지, 키로 풀면 무엇이 보이는지 본다",
                ["TCP handshake 뒤에 TLS handshake가 한 번 더", "SNI(접속할 사이트 이름)는 평문", "키 파일이 있으면 Wireshark가 복호화"],
                ["Wireshark: Edit → Preferences → Protocols → TLS 에 키 파일을 넣고 같은 캡처 다시 보기"],
                [Test("t05_https", "키 없이 vs 키를 넣고", "client.py로 HTTPS 요청을 보내며 키를 기록하고, 같은 캡처를 두 번 읽는다.",
                      ["① 표에는 TLS뿐", "② 표에는 GET / 와 200 OK"], t05_https, 10)]),
        Chapter("06", "06-link-layer-arp", "링크 계층: MAC과 ARP", "IP는 최종 목적지, MAC은 바로 다음 칸이라는 것을 본다",
                ["도착 MAC은 게이트웨이, 도착 IP는 example.com", "ARP: 'Who has IP?'를 브로드캐스트로 묻는다", "loopback에는 MAC이 없다"],
                ["01 캡처를 열어 맨 위 층이 Null/Loopback인 것 확인하기"],
                [Test("t06_mac", "MAC vs IP", "example.com에 HTTP 요청을 보내고 Ethernet 헤더와 IP 헤더를 나란히 본다.",
                      ["도착 MAC = arp -a의 게이트웨이 MAC"], t06_mac, 8),
                 Test("t06_arp", "ARP 직접 일으키기", "같은 네트워크의 안 쓰는 주소로 ping을 보내 ARP 요청을 일으킨다.",
                      ["도착 MAC ff:ff:ff:ff:ff:ff", "답이 없어 여러 번 묻는다"], t06_arp, 10)]),
        Chapter("07", "07-ip-icmp", "네트워크 계층: IP와 ICMP", "TTL, 라우터의 알림, IP 분할을 본다",
                ["TTL은 라우터마다 1씩 줄고 0이 되면 ICMP 타입 11로 알림", "MTU 1500보다 큰 패킷은 쪼개짐(같은 ID, 조각 위치)"],
                ["tracert -d example.com 을 끝까지 실행해 보기 (오래 걸림)"],
                [Test("t07_ttl", "ping과 TTL", "보통 ping, TTL=1 ping, TTL=2 ping을 보낸다.",
                      ["응답 TTL로 라우터 수 짐작", "TTL 초과를 보낸 라우터 주소"], t07_ttl, 14),
                 Test("t07_tracert", "tracert", "TTL을 1~4로 늘려 가며 3번씩 보낸다.",
                      ["TTL 1,1,1,2,2,2… 요청", "막힌 단계는 응답 없음"], t07_tracert, 18),
                 Test("t07_frag", "IP 분할", "3000바이트 ping을 보낸다.",
                      ["같은 ID, 조각 위치 0/1480/2960", "MF는 마지막만 False"], t07_frag, 7)]),
        Chapter("08", "08-tcp-deep", "전송 계층 심화", "RST, SYN 재전송, 흐름 제어, UDP를 본다",
                ["거절은 RST로 즉시, 무응답은 재전송하며 기다림", "Window = 받을 수 있는 남은 공간", "UDP는 연결·순서·재전송이 없다"],
                ["Wireshark: Statistics → TCP Stream Graphs → Window Scaling 으로 흐름 제어 그래프 보기"],
                [Test("t08_rst", "닫힌 포트 → RST", "아무도 기다리지 않는 9번 포트에 접속한다.", ["SYN/RST 쌍이 여러 번"], t08_rst, 6),
                 Test("t08_syn", "무응답 → SYN 재전송", "없는 주소 10.255.255.1에 9초 동안 접속을 시도한다.", ["간격 1 → 2 → 4초"], t08_syn, 14),
                 Test("t08_flow", "흐름 제어 (ZeroWindow)", "읽지 않는 서버에 계속 보낸다.", ["Win 8192 → 0", "Probe 간격이 늘어남", "5초 뒤 Window Update"], t08_flow, 12),
                 Test("t08_udp", "UDP", "UDP 에코 서버와 클라이언트.", ["패킷 2개뿐"], t08_udp, 6)]),
        Chapter("09", "09-encapsulation", "캡슐화 해부", "패킷 하나를 바이트 단위로 잘라 계층별 헤더를 직접 해석한다",
                ["각 헤더에 '다음은 무엇'을 알리는 칸: EtherType, IP 프로토콜, 포트", "내가 보낸 패킷의 IP 체크섬 0x0000은 checksum offload"],
                ["Wireshark에서 아무 패킷이나 Copy → as Hex Stream 해서 아래 입력 칸에 붙여 넣기"],
                [Test("t09_http", "HTTP 요청 패킷 해부", "example.com으로 간 HTTP 요청 하나를 잡아 dissect.py로 해부하고 tshark와 비교한다.",
                      ["바이트 위치 [시작..끝]", "체크섬 불일치 이유"], t09_http, 9),
                 Test("t09_udp", "loopback UDP 패킷 해부", "08의 UDP 패킷을 --link null로 해부한다.", ["링크 헤더 4바이트"], t09_udp, 7)]),
    ]
