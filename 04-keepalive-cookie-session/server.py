"""쿠키·세션·keep-alive 관찰용 HTTP/1.1 서버. 요청마다 클라이언트 포트를 출력해서 연결 재사용을 보여준다."""

import argparse
import html
import re
import secrets
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

MAX_BODY_BYTES = 1024
NAME_PATTERN = re.compile(r"^[0-9A-Za-z가-힣_-]{1,20}$")
COOKIE_NAME = "sid"


class SessionServer(ThreadingHTTPServer):
    """세션 저장소(sid → 이름)를 가진 HTTP 서버."""

    def __init__(self, address: tuple[str, int]) -> None:
        super().__init__(address, Handler)
        self.sessions: dict[str, str] = {}


class Handler(BaseHTTPRequestHandler):
    """/, /login, /me 를 처리한다."""

    # HTTP/1.1로 응답하면 Content-Length가 있는 한 연결을 닫지 않고 다음 요청을 기다린다(keep-alive).
    protocol_version = "HTTP/1.1"
    server: SessionServer

    def log_message(self, format: str, *args: object) -> None:
        """기본 로그에 클라이언트 포트를 덧붙인다. 포트가 같으면 같은 TCP 연결이다."""
        host, port = self.client_address[:2]
        print(f"[{host}:{port}] {format % args}")

    def send_text(self, status: int, body: str, content_type: str = "text/plain", headers: dict[str, str] | None = None) -> None:
        """본문과 Content-Length를 붙여 응답을 보낸다."""
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def current_user(self) -> str | None:
        """Cookie 헤더의 sid로 세션을 찾아 이름을 반환한다. 없거나 틀리면 None."""
        raw = self.headers.get("Cookie")
        if raw is None:
            return None
        try:
            cookie = SimpleCookie(raw)
        except CookieError:
            return None
        morsel = cookie.get(COOKIE_NAME)
        if morsel is None:
            return None
        return self.server.sessions.get(morsel.value)

    def do_GET(self) -> None:
        """GET / 은 로그인 폼, GET /me 는 세션 확인."""
        if self.path == "/":
            self.send_text(200, INDEX_HTML, "text/html")
        elif self.path == "/me":
            name = self.current_user()
            if name is None:
                self.send_text(401, "로그인하지 않았습니다. 쿠키가 없거나 모르는 sid입니다.\n")
            else:
                self.send_text(200, f"안녕하세요, {name}님. 쿠키의 sid로 당신을 알아봤습니다.\n")
        elif self.path == "/login":
            self.send_text(405, "/login 은 POST만 받습니다\n", headers={"Allow": "POST"})
        else:
            self.send_text(404, f"{self.path} 는 없는 경로입니다\n")

    def do_POST(self) -> None:
        """POST /login 은 name을 받아 세션을 만들고 Set-Cookie로 sid를 내려준다."""
        if self.path in ("/", "/me"):
            self.send_text(405, f"{self.path} 는 GET만 받습니다\n", headers={"Allow": "GET"})
            return
        if self.path != "/login":
            self.send_text(404, f"{self.path} 는 없는 경로입니다\n")
            return

        raw_length = self.headers.get("Content-Length", "")
        if not raw_length.isdigit():
            self.send_text(400, "Content-Length가 없거나 숫자가 아닙니다\n")
            return
        length = int(raw_length)
        if length > MAX_BODY_BYTES:
            # 본문을 읽지 않고 응답하므로, 남은 바이트가 다음 요청으로 오해되지 않게 연결을 닫는다.
            self.close_connection = True
            self.send_text(413, "본문이 너무 큽니다\n", headers={"Connection": "close"})
            return

        body = self.rfile.read(length).decode("utf-8", errors="replace")
        names = parse_qs(body).get("name", [])
        if len(names) != 1 or not NAME_PATTERN.match(names[0]):
            self.send_text(400, "name은 한글·영문·숫자·_- 로 1~20자여야 합니다 (예: name=kim)\n")
            return

        name = names[0]
        sid = secrets.token_hex(16)
        self.server.sessions[sid] = name
        print(f"    세션 생성: sid={sid} → {name} (현재 세션 {len(self.server.sessions)}개)")
        self.send_text(
            200,
            f"{html.escape(name)}님으로 로그인했습니다. <a href=\"/me\">/me 로 가기</a>\n",
            "text/html",
            {"Set-Cookie": f"{COOKIE_NAME}={sid}; Path=/; HttpOnly; SameSite=Lax"},
        )


INDEX_HTML = """<!doctype html>
<meta charset="utf-8">
<title>04 cookie session</title>
<h1>쿠키·세션 실습</h1>
<form method="post" action="/login">
  <input name="name" placeholder="이름 (예: kim)" required>
  <button>로그인</button>
</form>
<p><a href="/me">/me</a> — 로그인 상태 확인</p>
"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8001)
    args = parser.parse_args()

    server = SessionServer((args.host, args.port))
    print(f"[server] http://{args.host}:{args.port}/ 에서 대기 중 (Ctrl+C로 종료)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[server] 종료")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
