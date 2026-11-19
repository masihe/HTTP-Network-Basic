"""소켓으로 만든 HTTP 서버: 요청 바이트를 직접 읽고 파싱하고, 응답 바이트를 손으로 조립해서 보낸다."""

import argparse
import socket

MAX_HEADER_BYTES = 8 * 1024
MAX_BODY_BYTES = 64 * 1024
REASONS = {
    200: "OK",
    400: "Bad Request",
    404: "Not Found",
    405: "Method Not Allowed",
    413: "Content Too Large",
}
ROUTES = {"/": {"GET"}, "/echo": {"POST"}}


class BadRequest(Exception):
    """요청이 HTTP 형식에 맞지 않을 때 쓰는 예외. status에 돌려줄 상태 코드를 담는다."""

    def __init__(self, status: int, reason: str) -> None:
        super().__init__(reason)
        self.status = status


def read_head(conn: socket.socket) -> tuple[bytes, bytes]:
    """빈 줄(\\r\\n\\r\\n)이 나올 때까지 읽어 (헤더 부분, 이미 읽어버린 본문 앞부분)을 반환한다."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        if len(buf) > MAX_HEADER_BYTES:
            raise BadRequest(400, "헤더가 너무 김")
        chunk = conn.recv(1024)
        if not chunk:
            raise BadRequest(400, "빈 줄(\\r\\n\\r\\n) 전에 연결이 끊김")
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    return head, rest


def parse_head(head: bytes) -> tuple[str, str, str, dict[str, str]]:
    """헤더 바이트를 (메서드, 경로, 버전, 헤더 dict)로 나눈다. 헤더 이름은 소문자로 바꾼다."""
    try:
        text = head.decode("ascii")
    except UnicodeDecodeError as e:
        raise BadRequest(400, "헤더에 ASCII가 아닌 바이트가 있음") from e

    request_line, *header_lines = text.split("\r\n")
    parts = request_line.split(" ")
    if len(parts) != 3 or not parts[2].startswith("HTTP/1."):
        raise BadRequest(400, f"요청 줄 형식이 틀림: {request_line!r}")
    method, path, version = parts

    headers: dict[str, str] = {}
    for line in header_lines:
        name, sep, value = line.partition(":")
        if not sep or not name or name != name.strip():
            raise BadRequest(400, f"헤더 줄 형식이 틀림: {line!r}")
        headers[name.lower()] = value.strip()
    return method, path, version, headers


def read_body(conn: socket.socket, headers: dict[str, str], already: bytes) -> bytes:
    """Content-Length만큼 본문을 마저 읽어 반환한다. Content-Length가 없으면 본문이 없다고 본다."""
    raw = headers.get("content-length")
    if raw is None:
        return b""
    if not raw.isdigit():
        raise BadRequest(400, f"Content-Length가 숫자가 아님: {raw!r}")
    length = int(raw)
    if length > MAX_BODY_BYTES:
        raise BadRequest(413, f"본문이 너무 큼: {length}바이트")

    body = already
    while len(body) < length:
        chunk = conn.recv(1024)
        if not chunk:
            raise BadRequest(400, "본문을 다 받기 전에 연결이 끊김")
        body += chunk
    return body[:length]


def build_response(status: int, body: bytes, content_type: str, extra: dict[str, str] | None = None) -> bytes:
    """상태 줄, 헤더, 빈 줄, 본문을 이어 붙여 HTTP 응답 바이트를 만든다."""
    lines = [
        f"HTTP/1.1 {status} {REASONS[status]}",
        f"Content-Type: {content_type}",
        f"Content-Length: {len(body)}",
        "Connection: close",
    ]
    for name, value in (extra or {}).items():
        lines.append(f"{name}: {value}")
    head = "\r\n".join(lines) + "\r\n\r\n"
    return head.encode("ascii") + body


def route(method: str, path: str, body: bytes) -> bytes:
    """메서드와 경로에 맞는 응답 바이트를 만든다."""
    if path not in ROUTES:
        return build_response(404, f"{path} 는 없는 경로입니다\n".encode(), "text/plain; charset=utf-8")
    if method not in ROUTES[path]:
        allowed = ", ".join(sorted(ROUTES[path]))
        return build_response(
            405, f"{path} 는 {allowed} 만 받습니다\n".encode(), "text/plain; charset=utf-8", {"Allow": allowed}
        )
    if path == "/":
        html = "<h1>Hello HTTP</h1><p>이 응답은 server.py가 문자열로 직접 만들었습니다.</p>\n"
        return build_response(200, html.encode(), "text/html; charset=utf-8")
    return build_response(200, body, "application/octet-stream")  # POST /echo


def handle(conn: socket.socket) -> None:
    """연결 하나에서 요청 하나를 읽고 응답 하나를 보낸다."""
    try:
        head, rest = read_head(conn)
        print("----- 받은 요청 헤더 (원본 바이트) -----")
        print(repr(head + b"\r\n\r\n"))
        method, path, version, headers = parse_head(head)
        body = read_body(conn, headers, rest)
        if body:
            print(f"----- 받은 본문 {len(body)}바이트 -----")
            print(repr(body))
        response = route(method, path, body)
    except BadRequest as e:
        print(f"[server] 잘못된 요청 → {e.status}: {e}")
        response = build_response(e.status, f"{e}\n".encode(), "text/plain; charset=utf-8")

    print("----- 보낸 응답 (원본 바이트) -----")
    print(repr(response))
    print()
    conn.sendall(response)


def serve(host: str, port: int) -> None:
    """host:port에서 접속을 하나씩 받아 요청 하나를 처리하고 연결을 닫는다."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, port))
        listener.listen()
        print(f"[server] http://{host}:{port}/ 에서 대기 중 (Ctrl+C로 종료)\n")
        while True:
            conn, addr = listener.accept()
            with conn:
                conn.settimeout(10)
                print(f"[server] 연결됨: {addr}")
                try:
                    handle(conn)
                except TimeoutError:
                    print(f"[server] 10초 동안 요청이 끝나지 않아 연결을 닫음: {addr}\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    try:
        serve(args.host, args.port)
    except KeyboardInterrupt:
        print("\n[server] 종료")


if __name__ == "__main__":
    main()
